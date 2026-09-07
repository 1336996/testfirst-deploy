<#
.SYNOPSIS
    Creates a clean Azure DevOps Service Connection inventory for SharePoint.

.DESCRIPTION
    - Scans every Azure DevOps project visible to the PAT.
    - Lists each unique service connection once.
    - Gets service-connection metadata from Azure DevOps REST API 7.1.
    - Gets Microsoft Entra service-principal credential expiry dates from Microsoft Graph v1.0
      when the connection contains a serviceprincipalid.
    - Does NOT export secrets, passwords, private keys, or authorization secret values.
    - Produces one CSV for the SharePoint inventory and a separate CSV only for API errors.

.REQUIREMENTS
    - Windows PowerShell 5.1 or PowerShell 7+
    - Azure DevOps PAT with permission to read projects/service connections.
    - Azure CLI installed.
    - "az login" completed with an account that can read Microsoft Graph service principals
      if Entra credential expiry information is required.
#>

[CmdletBinding()]
param(
    [string]$Organization = "humana",
    [string]$OutputFolder = (Get-Location).Path
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# API versions -- intentionally kept separate.
# ---------------------------------------------------------------------------
$AdoApiVersion = "7.1"
$GraphApiVersion = "v1.0"

# ---------------------------------------------------------------------------
# Output files
# ---------------------------------------------------------------------------
$InventoryPath = Join-Path $OutputFolder "ADO-ServiceConnection-Inventory.csv"
$ErrorsPath    = Join-Path $OutputFolder "ADO-ServiceConnection-Inventory-Errors.csv"

# ---------------------------------------------------------------------------
# Helper: URL encode a path/query value
# ---------------------------------------------------------------------------
function ConvertTo-UrlEncoded {
    param([Parameter(Mandatory)][string]$Value)
    return [System.Uri]::EscapeDataString($Value)
}

# ---------------------------------------------------------------------------
# Helper: Invoke Azure DevOps REST API with PAT.
#
# IMPORTANT:
# All Azure DevOps REST calls in this script use api-version=7.1.
# ---------------------------------------------------------------------------
function Invoke-AdoGet {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    try {
        return Invoke-RestMethod `
            -Uri $Uri `
            -Headers $Headers `
            -Method Get `
            -ContentType "application/json"
    }
    catch {
        throw "ADO GET failed: $Uri`n$($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Helper: obtain a Microsoft Graph access token from the current Azure CLI
# login. No client secret is stored by this script.
# ---------------------------------------------------------------------------
function Get-GraphAccessToken {
    try {
        $token = az account get-access-token `
            --resource-type ms-graph `
            --query accessToken `
            -o tsv 2>$null

        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) {
            return $null
        }

        return $token.Trim()
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Helper: query Microsoft Graph for a service principal.
#
# Only metadata needed for inventory is requested.
# Secret VALUE is never requested/exported.
# ---------------------------------------------------------------------------
function Get-ServicePrincipalInfo {
    param(
        [Parameter(Mandatory)][string]$ObjectId,
        [Parameter(Mandatory)][hashtable]$Headers
    )

    $select = "id,appId,displayName,passwordCredentials,keyCredentials"
    $encodedObjectId = ConvertTo-UrlEncoded $ObjectId

    $uri = "https://graph.microsoft.com/$GraphApiVersion/servicePrincipals/$encodedObjectId" +
           "?`$select=$select"

    try {
        return Invoke-RestMethod `
            -Uri $uri `
            -Headers $Headers `
            -Method Get `
            -ContentType "application/json"
    }
    catch {
        return $null
    }
}

# ---------------------------------------------------------------------------
# Helper: convert credential collection to the single credential that matters
# for the inventory: the nearest future expiry. Expired credentials are used
# only when there is no future credential.
# ---------------------------------------------------------------------------
function Get-NearestCredential {
    param(
        [Parameter(Mandatory)]$ServicePrincipal
    )

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

# ---------------------------------------------------------------------------
# Helper: determine a useful authentication label.
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# Helper: renewal guidance. This is intentionally business-readable so the
# resulting CSV can be copied to SharePoint.
# ---------------------------------------------------------------------------
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

# ---------------------------------------------------------------------------
# START
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Azure DevOps Service Connection Inventory" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Organization : $Organization"
Write-Host "Output       : $InventoryPath"
Write-Host ""

# PAT
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

# Azure DevOps Basic authentication:
# username can be blank; PAT is the password.
$basicValue = [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes(":$pat")
)

$AdoHeaders = @{
    Authorization = "Basic $basicValue"
    Accept        = "application/json"
}

# Do not keep PAT around longer than necessary.
$pat = $null
$securePat = $null

# Try to obtain Graph token.
# The ADO inventory still works if Graph access is unavailable; only
# Entra credential fields will be marked unavailable.
$graphToken = Get-GraphAccessToken

$GraphHeaders = $null

if ($graphToken) {
    $GraphHeaders = @{
        Authorization = "Bearer $graphToken"
        Accept        = "application/json"
    }
    Write-Host "Microsoft Graph access: available" -ForegroundColor Green
}
else {
    Write-Warning "Microsoft Graph access is not available. ADO service-connection inventory will continue, but Entra credential expiry fields may be unavailable."
}

# ---------------------------------------------------------------------------
# Get ALL projects with continuation-token handling.
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "Getting Azure DevOps projects..." -ForegroundColor Yellow

$projects = @()
$continuationToken = $null

do {
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

} while ($continuationToken)

Write-Host "Projects found: $($projects.Count)" -ForegroundColor Green

# ---------------------------------------------------------------------------
# Scan every project.
#
# We intentionally list endpoints from each project and then de-duplicate
# by service connection ID. This prevents the 13,000-row duplication problem.
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

    # includeDetails=true is important because we need metadata such as
    # createdBy/creationDate where the service endpoint API returns it.
    $endpointUri =
        "https://dev.azure.com/$Organization/$projectEncoded/_apis/serviceendpoint/endpoints" +
        "?includeDetails=true&api-version=$AdoApiVersion"

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

        # First time seeing this service connection.
        if (-not $inventoryById.ContainsKey($endpointId)) {

            $authType = Get-AuthenticationType -Endpoint $endpoint

            $spObjectId = $null

            # Azure RM service connections normally expose the SP object ID
            # in data.serviceprincipalid. Keep the lookup conservative so
            # unrelated service connection types are not incorrectly mapped.
            if ($endpoint.data) {
                foreach ($propertyName in @(
                    "serviceprincipalid",
                    "servicePrincipalId",
                    "servicePrincipalObjectId",
                    "serviceprincipalobjectid"
                )) {
                    $candidate = $endpoint.data.PSObject.Properties[$propertyName]

                    if ($candidate -and
                        -not [string]::IsNullOrWhiteSpace([string]$candidate.Value)) {

                        $spObjectId = [string]$candidate.Value
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
                                                ([DateTime]$endpoint.creationDate).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
                                            } else { "Not exposed" }
                CreatedBy                = if ($endpoint.createdBy.displayName) {
                                                [string]$endpoint.createdBy.displayName
                                            } else { "Not exposed" }
                CreatedByUPN             = if ($endpoint.createdBy.uniqueName) {
                                                [string]$endpoint.createdBy.uniqueName
                                            } else { "Not exposed" }
                Owner                    = if ($endpoint.owner) {
                                                [string]$endpoint.owner
                                            } else { "Not specified" }
                Projects                 = New-Object System.Collections.Generic.List[string]
                ServicePrincipalObjectId = $spObjectId
                ServicePrincipal         = ""
                ApplicationId            = ""
                TenantId                 = ""
                Subscription             = ""
                SubscriptionId           = ""
                CredentialType           = ""
                CredentialDisplayName    = ""
                CredentialExpiration     = ""
                CredentialStatus         = ""
                RenewalProcess           = ""
            }
        }

        $record = $inventoryById[$endpointId]

        # Add the current project once.
        if (-not $record.Projects.Contains($projectName)) {
            [void]$record.Projects.Add($projectName)
        }

        # If a later project response has the SP ID and the first did not,
        # retain it.
        if ([string]::IsNullOrWhiteSpace($record.ServicePrincipalObjectId) -and
            $endpoint.data) {

            foreach ($propertyName in @(
                "serviceprincipalid",
                "servicePrincipalId",
                "servicePrincipalObjectId",
                "serviceprincipalobjectid"
            )) {
                $candidate = $endpoint.data.PSObject.Properties[$propertyName]

                if ($candidate -and
                    -not [string]::IsNullOrWhiteSpace([string]$candidate.Value)) {

                    $record.ServicePrincipalObjectId = [string]$candidate.Value
                    break
                }
            }
        }

        # Azure RM-specific subscription / tenant metadata.
        if ($endpoint.data) {

            if ([string]::IsNullOrWhiteSpace($record.SubscriptionId)) {
                foreach ($p in @("subscriptionId","subscriptionid")) {
                    $candidate = $endpoint.data.PSObject.Properties[$p]
                    if ($candidate -and $candidate.Value) {
                        $record.SubscriptionId = [string]$candidate.Value
                        break
                    }
                }
            }

            if ([string]::IsNullOrWhiteSpace($record.Subscription)) {
                foreach ($p in @("subscriptionName","subscriptionname")) {
                    $candidate = $endpoint.data.PSObject.Properties[$p]
                    if ($candidate -and $candidate.Value) {
                        $record.Subscription = [string]$candidate.Value
                        break
                    }
                }
            }

            if ([string]::IsNullOrWhiteSpace($record.TenantId)) {
                foreach ($p in @("tenantid","tenantId")) {
                    $candidate = $endpoint.data.PSObject.Properties[$p]
                    if ($candidate -and $candidate.Value) {
                        $record.TenantId = [string]$candidate.Value
                        break
                    }
                }
            }
        }
    }
}

Write-Progress -Activity "Scanning Azure DevOps service connections" -Completed

# ---------------------------------------------------------------------------
# Enrich service-principal records with Microsoft Graph.
# Cache by SP object ID so the same SP is never queried repeatedly.
# ---------------------------------------------------------------------------
$graphCache = @{}

$records = @($inventoryById.Values)

Write-Host ""
Write-Host "Unique service connections found: $($records.Count)" -ForegroundColor Green

if ($GraphHeaders) {
    Write-Host "Reading Entra service-principal credential metadata..." -ForegroundColor Yellow
}

foreach ($record in $records) {

    if ([string]::IsNullOrWhiteSpace($record.ServicePrincipalObjectId)) {
        $record.RenewalProcess = Get-RenewalProcess `
            -AuthType $record.Authentication `
            -CredentialType $record.CredentialType
        continue
    }

    if (-not $GraphHeaders) {
        $record.CredentialType = "Graph access unavailable"
        $record.CredentialStatus = "Not determined"
        $record.CredentialExpiration = "Not available"
        $record.RenewalProcess = "Run 'az login' with an account permitted to read Microsoft Graph service principals, then rerun the inventory."
        continue
    }

    $spId = $record.ServicePrincipalObjectId

    if ($graphCache.ContainsKey($spId)) {
        $sp = $graphCache[$spId]
    }
    else {
        $sp = Get-ServicePrincipalInfo `
            -ObjectId $spId `
            -Headers $GraphHeaders

        $graphCache[$spId] = $sp
    }

    if ($null -eq $sp) {
        $record.ServicePrincipal = "Unable to read from Microsoft Graph"
        $record.CredentialStatus = "Not determined"
        $record.CredentialExpiration = "Not available"
        $record.RenewalProcess = "Verify Microsoft Graph service-principal read permission and rerun."
        continue
    }

    $record.ServicePrincipal = [string]$sp.displayName
    $record.ApplicationId = [string]$sp.appId

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

        $record.RenewalProcess = Get-RenewalProcess `
            -AuthType $record.Authentication `
            -CredentialType $record.CredentialType
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
        $record.RenewalProcess = Get-RenewalProcess `
            -AuthType $record.Authentication `
            -CredentialType $record.CredentialType
    }
}

# ---------------------------------------------------------------------------
# Final CSV shape.
# Projects are joined into ONE field so one service connection = one row.
# ---------------------------------------------------------------------------
$finalRows = foreach ($record in ($records | Sort-Object ServiceConnection, ServiceConnectionId)) {

    [pscustomobject][ordered]@{
        Organization              = $Organization
        Projects                  = (($record.Projects | Sort-Object) -join "; ")
        ServiceConnection         = $record.ServiceConnection
        Type                      = $record.Type
        Authentication            = $record.Authentication
        CreatedDate               = $record.CreatedDate
        CreatedBy                 = $record.CreatedBy
        CreatedByUPN              = $record.CreatedByUPN
        Owner                     = $record.Owner
        ServicePrincipal          = $record.ServicePrincipal
        ServicePrincipalObjectId  = $record.ServicePrincipalObjectId
        ApplicationId             = $record.ApplicationId
        Subscription              = $record.Subscription
        SubscriptionId            = $record.SubscriptionId
        TenantId                  = $record.TenantId
        CredentialType            = $record.CredentialType
        CredentialDisplayName     = $record.CredentialDisplayName
        CredentialExpiration      = $record.CredentialExpiration
        CredentialStatus          = $record.CredentialStatus
        RenewalProcess             = $record.RenewalProcess
    }
}

# Export UTF-8 CSV.
$finalRows | Export-Csv `
    -Path $InventoryPath `
    -NoTypeInformation `
    -Encoding UTF8

if ($errors.Count -gt 0) {
    $errors | Export-Csv `
        -Path $ErrorsPath `
        -NoTypeInformation `
        -Encoding UTF8
}
elseif (Test-Path $ErrorsPath) {
    Remove-Item $ErrorsPath -Force
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " Inventory completed successfully" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host "Projects scanned           : $($projects.Count)"
Write-Host "Unique service connections : $($finalRows.Count)"
Write-Host "Project/API errors         : $($errors.Count)"
Write-Host ""
Write-Host "Inventory CSV:"
Write-Host $InventoryPath -ForegroundColor Cyan

if ($errors.Count -gt 0) {
    Write-Host ""
    Write-Host "Errors CSV:"
    Write-Host $ErrorsPath -ForegroundColor Yellow
}

Write-Host ""
Write-Host "No service-connection secret values were exported." -ForegroundColor Green
