<##
.SYNOPSIS
    Creates a clean Azure DevOps Service Connection inventory for SharePoint.

.DESCRIPTION
    Scans all Azure DevOps projects visible to the PAT, lists each unique service
    connection once, and enriches AzureRM service connections with Microsoft Entra
    service-principal credential information.

    IMPORTANT FIX:
    Azure DevOps serviceendpoint data can contain serviceprincipalid as the
    Application (Client) ID rather than the Entra Service Principal Object ID.
    The script therefore tries Microsoft Graph using BOTH identifiers:
      1. servicePrincipals/{id}
      2. servicePrincipals(appId='{id}')
    This prevents the previous "Graph lookup failed" problem caused by treating
    the ADO serviceprincipalid as only an Object ID.

    Secrets/private keys are never exported.

.REQUIREMENTS
    - Windows PowerShell 5.1 or PowerShell 7+
    - Azure DevOps PAT with permission to read projects and service connections
    - Azure CLI installed
    - az login completed against the tenant containing the service principals
    - The signed-in account must be allowed to read service-principal metadata
      in Microsoft Graph. Application.Read.All / Directory Readers or an
      equivalent supported directory role may be required.
#>

[CmdletBinding()]
param(
    [string]$Organization = "humana",
    [string]$OutputFolder = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

$AdoApiVersion = "7.1"
$GraphApiVersion = "v1.0"

$InventoryPath = Join-Path $OutputFolder "ADO-ServiceConnection-Inventory.csv"
$ErrorsPath    = Join-Path $OutputFolder "ADO-ServiceConnection-Inventory-Errors.csv"

function ConvertTo-UrlEncoded {
    param([Parameter(Mandatory)][string]$Value)
    [System.Uri]::EscapeDataString($Value)
}

function Invoke-AdoGet {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    try {
        Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -ContentType "application/json"
    }
    catch {
        throw "ADO GET failed: $Uri`n$($_.Exception.Message)"
    }
}

function Invoke-GraphGetWithAz {
    param([Parameter(Mandatory)][string]$Uri)

    # Use the same Azure CLI authentication path that is already known to work
    # in the user's environment (az rest against graph.microsoft.com).
    $output = @(& az rest --method GET --url $Uri --only-show-errors 2>&1)
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        $message = ($output | ForEach-Object { $_.ToString() }) -join " "
        throw "Graph request failed (exit code $exitCode): $message"
    }

    $jsonText = ($output | ForEach-Object { $_.ToString() }) -join [Environment]::NewLine

    if ([string]::IsNullOrWhiteSpace($jsonText)) {
        throw "Graph returned an empty response."
    }

    try {
        $jsonText | ConvertFrom-Json
    }
    catch {
        throw "Graph returned non-JSON output: $jsonText"
    }
}

function Get-ServicePrincipalInfo {
    param(
        [Parameter(Mandatory)][string]$Identifier
    )

    $encoded = ConvertTo-UrlEncoded $Identifier
    $select = "id,appId,displayName,passwordCredentials,keyCredentials"

    # Attempt 1: treat the value as the Entra Service Principal Object ID.
    $objectUri = "https://graph.microsoft.com/$GraphApiVersion/servicePrincipals/$encoded?`$select=$select"

    try {
        return [pscustomobject]@{
            Data       = Invoke-GraphGetWithAz -Uri $objectUri
            LookupType = "ObjectId"
            Error      = $null
        }
    }
    catch {
        $objectError = $_.Exception.Message
    }

    # Attempt 2: treat the value as the Application (Client) ID.
    # Microsoft Graph explicitly supports /servicePrincipals(appId='{appId}').
    $appUri = "https://graph.microsoft.com/$GraphApiVersion/servicePrincipals(appId='$encoded')?`$select=$select"

    try {
        return [pscustomobject]@{
            Data       = Invoke-GraphGetWithAz -Uri $appUri
            LookupType = "ApplicationId"
            Error      = $null
        }
    }
    catch {
        $appError = $_.Exception.Message
    }

    return [pscustomobject]@{
        Data       = $null
        LookupType = $null
        Error      = "ObjectId lookup: $objectError | ApplicationId lookup: $appError"
    }
}

function Get-NearestCredential {
    param([Parameter(Mandatory)]$ServicePrincipal)

    $items = @()

    foreach ($credential in @($ServicePrincipal.passwordCredentials)) {
        if ($credential.endDateTime) {
            $items += [pscustomobject]@{
                CredentialType = "Client Secret"
                DisplayName    = [string]$credential.displayName
                StartDate      = [string]$credential.startDateTime
                EndDate        = [string]$credential.endDateTime
            }
        }
    }

    foreach ($credential in @($ServicePrincipal.keyCredentials)) {
        if ($credential.endDateTime) {
            $items += [pscustomobject]@{
                CredentialType = "Certificate/Key"
                DisplayName    = [string]$credential.displayName
                StartDate      = [string]$credential.startDateTime
                EndDate        = [string]$credential.endDateTime
            }
        }
    }

    if ($items.Count -eq 0) {
        return $null
    }

    $now = [DateTime]::UtcNow

    $future = @(
        $items |
        Where-Object {
            try { ([DateTime]$_.EndDate) -gt $now } catch { $false }
        } |
        Sort-Object {
            try { [DateTime]$_.EndDate } catch { [DateTime]::MaxValue }
        }
    )

    if ($future.Count -gt 0) {
        return $future[0]
    }

    return @(
        $items |
        Sort-Object {
            try { [DateTime]$_.EndDate } catch { [DateTime]::MinValue }
        } -Descending
    )[0]
}

function Get-AuthenticationType {
    param([Parameter(Mandatory)]$Endpoint)

    $scheme = [string]$Endpoint.authorization.scheme
    if (-not [string]::IsNullOrWhiteSpace($scheme)) {
        return $scheme
    }

    if ($Endpoint.data.authenticationType) {
        return [string]$Endpoint.data.authenticationType
    }

    return "Not specified"
}

function Get-RenewalProcess {
    param(
        [string]$AuthType,
        [string]$CredentialType
    )

    $text = "$AuthType $CredentialType".ToLowerInvariant()

    if ($text -match "workloadidentity|federated|federation") {
        return "No client-secret expiry. Review the Entra federated credential and Azure DevOps service connection configuration if access changes."
    }

    if ($text -match "managedidentity") {
        return "No client-secret expiry. Maintain the Azure managed identity and its Azure RBAC permissions."
    }

    if ($text -match "serviceprincipal|spn|clientsecret|secret|certificate") {
        return "Renew the Entra service-principal credential before expiry, then update/verify the Azure DevOps service connection."
    }

    return "Review the authentication method in Azure DevOps and renew/replace the credential according to that provider's process."
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Azure DevOps Service Connection Inventory" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Organization : $Organization"
Write-Host "Output       : $InventoryPath"
Write-Host ""

# Validate Azure CLI login before doing the large ADO scan.
try {
    $null = az account show --only-show-errors 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI is not logged in. Run: az login"
    }
}
catch {
    throw $_.Exception.Message
}

$securePat = Read-Host "Enter Azure DevOps PAT" -AsSecureString
$patPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePat)
try {
    $pat = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($patPtr)
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($patPtr)
}

if ([string]::IsNullOrWhiteSpace($pat)) {
    throw "PAT cannot be empty."
}

$basicValue = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$pat"))
$AdoHeaders = @{
    Authorization = "Basic $basicValue"
    Accept        = "application/json"
}

$pat = $null
$securePat = $null

# ---------------------------------------------------------------------------
# Get all projects.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Getting Azure DevOps projects..." -ForegroundColor Yellow

$projects = @()
$continuationToken = $null

while ($true) {
    $uri = "https://dev.azure.com/$Organization/_apis/projects?stateFilter=wellFormed&`$top=100&api-version=$AdoApiVersion"

    if ($continuationToken) {
        $encodedToken = ConvertTo-UrlEncoded $continuationToken
        $uri = "https://dev.azure.com/$Organization/_apis/projects?stateFilter=wellFormed&`$top=100&continuationToken=$encodedToken&api-version=$AdoApiVersion"
    }

    try {
        $responseHeaders = $null
        $page = Invoke-WebRequest `
            -Uri $uri `
            -Headers $AdoHeaders `
            -Method Get `
            -ContentType "application/json" `
            -UseBasicParsing `
            -ResponseHeadersVariable responseHeaders

        $body = $page.Content | ConvertFrom-Json

        if ($body.value) {
            $projects += @($body.value)
        }

        $continuationToken = $null
        if ($responseHeaders) {
            $headerKey = $responseHeaders.Keys |
                Where-Object { $_ -ieq "x-ms-continuationtoken" } |
                Select-Object -First 1

            if ($headerKey) {
                $continuationToken = [string]$responseHeaders[$headerKey]
            }
        }
    }
    catch {
        throw "Unable to retrieve Azure DevOps projects.`n$($_.Exception.Message)"
    }

    if (-not $continuationToken) {
        break
    }
}

Write-Host "Projects found: $($projects.Count)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Scan projects and de-duplicate by service connection ID.
# ---------------------------------------------------------------------------
$inventoryById = @{}
$errors = @()
$projectNumber = 0

foreach ($project in $projects) {
    $projectNumber++

    Write-Progress `
        -Activity "Scanning Azure DevOps service connections" `
        -Status "$projectNumber / $($projects.Count): $($project.name)" `
        -PercentComplete (($projectNumber / [math]::Max($projects.Count,1)) * 100)

    $projectId = [string]$project.id
    $projectName = [string]$project.name
    $projectEncoded = ConvertTo-UrlEncoded $projectId

    $endpointUri = "https://dev.azure.com/$Organization/$projectEncoded/_apis/serviceendpoint/endpoints?includeDetails=true&api-version=$AdoApiVersion"

    try {
        $endpointResponse = Invoke-AdoGet -Uri $endpointUri -Headers $AdoHeaders
    }
    catch {
        $errors += [pscustomobject]@{
            ProjectId   = $projectId
            ProjectName = $projectName
            Error       = $_.Exception.Message
        }
        Write-Warning "Could not read service connections from '$projectName'."
        continue
    }

    foreach ($endpoint in @($endpointResponse.value)) {
        if (-not $endpoint.id) {
            continue
        }

        $endpointId = [string]$endpoint.id

        if (-not $inventoryById.ContainsKey($endpointId)) {
            $authType = Get-AuthenticationType -Endpoint $endpoint
            $spIdentifier = $null

            if ($endpoint.data) {
                foreach ($propertyName in @(
                    "serviceprincipalid",
                    "servicePrincipalId",
                    "servicePrincipalObjectId",
                    "serviceprincipalobjectid"
                )) {
                    $candidate = $endpoint.data.PSObject.Properties[$propertyName]
                    if ($candidate -and -not [string]::IsNullOrWhiteSpace([string]$candidate.Value)) {
                        $spIdentifier = [string]$candidate.Value
                        break
                    }
                }
            }

            $inventoryById[$endpointId] = [ordered]@{
                ServiceConnectionId       = $endpointId
                ServiceConnection         = [string]$endpoint.name
                Type                     = [string]$endpoint.type
                Authentication           = $authType
                CreatedDate              = if ($endpoint.creationDate) {
                                                try { ([DateTime]$endpoint.creationDate).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'") }
                                                catch { [string]$endpoint.creationDate }
                                            } else { "Not exposed" }
                CreatedBy                = if ($endpoint.createdBy.displayName) { [string]$endpoint.createdBy.displayName } else { "Not exposed" }
                CreatedByUPN              = if ($endpoint.createdBy.uniqueName) { [string]$endpoint.createdBy.uniqueName } else { "Not exposed" }
                Owner                    = if ($endpoint.owner) { [string]$endpoint.owner } else { "Not specified" }
                Projects                 = New-Object System.Collections.Generic.List[string]
                ServicePrincipalIdFromADO = $spIdentifier
                ServicePrincipal         = ""
                ServicePrincipalObjectId = ""
                ApplicationId            = ""
                TenantId                 = ""
                Subscription             = ""
                SubscriptionId           = ""
                CredentialType           = ""
                CredentialDisplayName    = ""
                CredentialExpiration     = ""
                CredentialStatus         = ""
                RenewalProcess           = ""
                GraphLookupStatus        = ""
            }
        }

        $record = $inventoryById[$endpointId]

        if (-not $record.Projects.Contains($projectName)) {
            [void]$record.Projects.Add($projectName)
        }

        if ($endpoint.data) {
            if ([string]::IsNullOrWhiteSpace($record.ServicePrincipalIdFromADO)) {
                foreach ($propertyName in @("serviceprincipalid","servicePrincipalId","servicePrincipalObjectId","serviceprincipalobjectid")) {
                    $candidate = $endpoint.data.PSObject.Properties[$propertyName]
                    if ($candidate -and -not [string]::IsNullOrWhiteSpace([string]$candidate.Value)) {
                        $record.ServicePrincipalIdFromADO = [string]$candidate.Value
                        break
                    }
                }
            }

            foreach ($p in @("subscriptionId","subscriptionid")) {
                if ([string]::IsNullOrWhiteSpace($record.SubscriptionId)) {
                    $candidate = $endpoint.data.PSObject.Properties[$p]
                    if ($candidate -and $candidate.Value) {
                        $record.SubscriptionId = [string]$candidate.Value
                    }
                }
            }

            foreach ($p in @("subscriptionName","subscriptionname")) {
                if ([string]::IsNullOrWhiteSpace($record.Subscription)) {
                    $candidate = $endpoint.data.PSObject.Properties[$p]
                    if ($candidate -and $candidate.Value) {
                        $record.Subscription = [string]$candidate.Value
                    }
                }
            }

            foreach ($p in @("tenantid","tenantId")) {
                if ([string]::IsNullOrWhiteSpace($record.TenantId)) {
                    $candidate = $endpoint.data.PSObject.Properties[$p]
                    if ($candidate -and $candidate.Value) {
                        $record.TenantId = [string]$candidate.Value
                    }
                }
            }
        }
    }
}

Write-Progress -Activity "Scanning Azure DevOps service connections" -Completed

$records = @($inventoryById.Values)
Write-Host ""
Write-Host "Unique service connections found: $($records.Count)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Enrich service principals.
# ---------------------------------------------------------------------------
$graphCache = @{}
$graphRequests = 0
$graphFailures = 0

Write-Host "Reading Microsoft Entra service-principal credential metadata..." -ForegroundColor Yellow

foreach ($record in $records) {
    $identifier = [string]$record.ServicePrincipalIdFromADO

    if ([string]::IsNullOrWhiteSpace($identifier)) {
        $record.GraphLookupStatus = "Not applicable"
        $record.RenewalProcess = Get-RenewalProcess -AuthType $record.Authentication -CredentialType $record.CredentialType
        continue
    }

    if ($graphCache.ContainsKey($identifier)) {
        $lookup = $graphCache[$identifier]
    }
    else {
        # Graph documents a limit of 150 requests/minute for selecting keyCredentials.
        # Keep the script comfortably below that limit.
        if ($graphRequests -ge 100 -and (($graphRequests % 100) -eq 0)) {
            Write-Host "Pausing briefly to avoid Microsoft Graph credential-metadata throttling..." -ForegroundColor DarkYellow
            Start-Sleep -Seconds 15
        }

        $lookup = Get-ServicePrincipalInfo -Identifier $identifier
        $graphCache[$identifier] = $lookup
        $graphRequests++
    }

    if ($lookup.Data) {
        $sp = $lookup.Data

        $record.ServicePrincipal = [string]$sp.displayName
        $record.ServicePrincipalObjectId = [string]$sp.id
        $record.ApplicationId = [string]$sp.appId
        $record.GraphLookupStatus = "Success ($($lookup.LookupType))"

        $credential = Get-NearestCredential -ServicePrincipal $sp

        if ($credential) {
            $record.CredentialType = $credential.CredentialType
            $record.CredentialDisplayName = $credential.DisplayName

            try {
                $expiry = ([DateTime]$credential.EndDate).ToUniversalTime()
                $record.CredentialExpiration = $expiry.ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
                $days = [math]::Floor(($expiry - [DateTime]::UtcNow).TotalDays)

                if ($days -lt 0) {
                    $record.CredentialStatus = "EXPIRED"
                }
                elseif ($days -le 30) {
                    $record.CredentialStatus = "Expires within 30 days"
                }
                elseif ($days -le 90) {
                    $record.CredentialStatus = "Expires within 90 days"
                }
                else {
                    $record.CredentialStatus = "Active"
                }
            }
            catch {
                $record.CredentialExpiration = "Not determined"
                $record.CredentialStatus = "Not determined"
            }
        }
        else {
            if ($record.Authentication -match "WorkloadIdentity|Federated|ManagedIdentity") {
                $record.CredentialType = "No expiring secret/certificate exposed"
                $record.CredentialStatus = "Not applicable"
            }
            else {
                $record.CredentialType = "No credential returned"
                $record.CredentialStatus = "Not determined"
            }
            $record.CredentialExpiration = "Not applicable"
        }

        $record.RenewalProcess = Get-RenewalProcess -AuthType $record.Authentication -CredentialType $record.CredentialType
    }
    else {
        $graphFailures++
        $record.GraphLookupStatus = "FAILED"
        $record.CredentialType = "Graph lookup failed"
        $record.CredentialExpiration = "Not available"
        $record.CredentialStatus = "Graph lookup failed"
        $record.RenewalProcess = "Verify Microsoft Graph access and confirm the ADO service-principal identifier is valid."

        $errors += [pscustomobject]@{
            ProjectId   = ""
            ProjectName = (($record.Projects | Sort-Object) -join "; ")
            Error       = "Service connection '$($record.ServiceConnection)': $($lookup.Error)"
        }
    }
}

# ---------------------------------------------------------------------------
# Final SharePoint-friendly output: exactly one row per unique connection.
# ---------------------------------------------------------------------------
$finalRows = foreach ($record in ($records | Sort-Object ServiceConnection, ServiceConnectionId)) {
    [pscustomobject][ordered]@{
        Organization             = $Organization
        Projects                 = (($record.Projects | Sort-Object) -join "; ")
        ServiceConnection        = $record.ServiceConnection
        Type                     = $record.Type
        Authentication           = $record.Authentication
        CreatedDate              = $record.CreatedDate
        CreatedBy                = $record.CreatedBy
        CreatedByUPN             = $record.CreatedByUPN
        Owner                    = $record.Owner
        ServicePrincipal         = $record.ServicePrincipal
        ServicePrincipalObjectId = $record.ServicePrincipalObjectId
        ApplicationId            = $record.ApplicationId
        Subscription             = $record.Subscription
        SubscriptionId           = $record.SubscriptionId
        TenantId                 = $record.TenantId
        CredentialType           = $record.CredentialType
        CredentialDisplayName    = $record.CredentialDisplayName
        CredentialExpiration     = $record.CredentialExpiration
        CredentialStatus         = $record.CredentialStatus
        RenewalProcess           = $record.RenewalProcess
        GraphLookupStatus        = $record.GraphLookupStatus
    }
}

$finalRows | Export-Csv -Path $InventoryPath -NoTypeInformation -Encoding UTF8

if ($errors.Count -gt 0) {
    $errors | Export-Csv -Path $ErrorsPath -NoTypeInformation -Encoding UTF8
}
elseif (Test-Path $ErrorsPath) {
    Remove-Item $ErrorsPath -Force
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " Inventory completed" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Projects scanned           : $($projects.Count)"
Write-Host "Unique service connections : $($finalRows.Count)"
Write-Host "Graph requests             : $graphRequests"
Write-Host "Graph lookup failures      : $graphFailures"
Write-Host "Total errors               : $($errors.Count)"
Write-Host ""
Write-Host "Inventory CSV:" -ForegroundColor Cyan
Write-Host $InventoryPath -ForegroundColor Cyan

if ($errors.Count -gt 0) {
    Write-Host ""
    Write-Host "Errors CSV:" -ForegroundColor Yellow
    Write-Host $ErrorsPath -ForegroundColor Yellow
}

Write-Host ""
Write-Host "No service-connection secret values or private keys were exported." -ForegroundColor Green
