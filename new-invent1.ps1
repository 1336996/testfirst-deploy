[CmdletBinding()]
param(
    [string]$Organization = "humana",
    [string]$OutputFolder = (Join-Path (Get-Location) "ADO-ServiceConnection-Inventory"),
    [switch]$IncludeNonAzureServiceConnections
)

$ErrorActionPreference = "Stop"

# ------------------------------------------------------------
# Azure DevOps Service Connection Inventory
# Read-only script.
#
# Collects:
# - Project
# - Service connection name/type/id
# - ADO service connection creation date
# - ADO service connection created by
# - Azure subscription/tenant details where available
# - Service principal object ID / application ID
# - Entra credential type/name/start/end date
# - Credential status
# - Suggested renewal process
#
# Requirements:
# 1. PowerShell 5.1+ / PowerShell 7+
# 2. PAT with permission to read service endpoints/projects
# 3. Azure CLI installed
# 4. az login completed with an account allowed to read the required
#    Microsoft Graph service principal data
#
# The script never exports secret values.
# ------------------------------------------------------------

function Write-Section {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 72) -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ("=" * 72) -ForegroundColor Cyan
}

function Get-StringProperty {
    param(
        [object]$Object,
        [string[]]$Names
    )

    if ($null -eq $Object) { return $null }

    foreach ($name in $Names) {
        $p = $Object.PSObject.Properties | Where-Object { $_.Name -ieq $name } | Select-Object -First 1
        if ($null -ne $p -and $null -ne $p.Value) {
            $value = [string]$p.Value
            if (-not [string]::IsNullOrWhiteSpace($value)) {
                return $value
            }
        }
    }

    return $null
}

function Get-NestedString {
    param(
        [object]$Object,
        [string]$Path
    )

    if ($null -eq $Object) { return $null }

    $current = $Object

    foreach ($part in ($Path -split '\.')) {
        if ($null -eq $current) { return $null }

        $p = $current.PSObject.Properties | Where-Object { $_.Name -ieq $part } | Select-Object -First 1
        if ($null -eq $p) { return $null }

        $current = $p.Value
    }

    if ($null -eq $current) { return $null }

    $value = [string]$current
    if ([string]::IsNullOrWhiteSpace($value)) { return $null }

    return $value
}

function Get-HeaderValue {
    param(
        [object]$Headers,
        [string]$Name
    )

    if ($null -eq $Headers) { return $null }

    foreach ($key in $Headers.Keys) {
        if ($key -ieq $Name) {
            $value = $Headers[$key]
            if ($value -is [System.Array]) {
                return ($value -join "")
            }
            return [string]$value
        }
    }

    return $null
}

function Invoke-AdoGet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [int]$MaxAttempts = 3
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            $response = Invoke-WebRequest `
                -Uri $Uri `
                -Headers $Headers `
                -Method Get `
                -UseBasicParsing `
                -ErrorAction Stop

            $content = [string]$response.Content

            if ([string]::IsNullOrWhiteSpace($content)) {
                throw "Azure DevOps returned an empty response."
            }

            try {
                $json = $content | ConvertFrom-Json -ErrorAction Stop
            }
            catch {
                $preview = $content.Substring(0, [Math]::Min(250, $content.Length))
                throw "Azure DevOps returned non-JSON content. First characters: $preview"
            }

            return [PSCustomObject]@{
                Body    = $json
                Headers = $response.Headers
            }
        }
        catch {
            if ($attempt -eq $MaxAttempts) {
                throw
            }

            Start-Sleep -Seconds ([Math]::Pow(2, $attempt))
        }
    }
}

function Get-AdoProjects {
    param(
        [string]$Org,
        [hashtable]$Headers
    )

    $allProjects = @()
    $continuation = $null

    do {
        $uri = "https://dev.azure.com/$Org/_apis/projects?api-version=7.1&`$top=100"

        if (-not [string]::IsNullOrWhiteSpace($continuation)) {
            $encoded = [Uri]::EscapeDataString($continuation)
            $uri += "&continuationToken=$encoded"
        }

        $result = Invoke-AdoGet -Uri $uri -Headers $Headers

        if ($null -ne $result.Body.value) {
            $allProjects += @($result.Body.value)
        }

        $continuation = Get-HeaderValue -Headers $result.Headers -Name "x-ms-continuationtoken"

    } while (-not [string]::IsNullOrWhiteSpace($continuation))

    return @($allProjects)
}

function Get-ServiceEndpoints {
    param(
        [string]$Org,
        [string]$ProjectId,
        [hashtable]$Headers
    )

    # The standard Service Endpoint GET returns the ServiceEndpoint object.
    # creationDate is part of the ServiceEndpoint model and is used directly
    # when the service returns it.
    $uri = "https://dev.azure.com/$Org/$ProjectId/_apis/serviceendpoint/endpoints?api-version=7.1"

    $result = Invoke-AdoGet -Uri $uri -Headers $Headers

    if ($null -eq $result.Body.value) {
        return @()
    }

    return @($result.Body.value)
}

function Get-ServicePrincipalId {
    param([object]$Endpoint)

    $candidates = @(
        (Get-NestedString $Endpoint "data.serviceprincipalid"),
        (Get-NestedString $Endpoint "data.servicePrincipalId"),
        (Get-NestedString $Endpoint "authorization.parameters.serviceprincipalid"),
        (Get-NestedString $Endpoint "authorization.parameters.servicePrincipalId"),
        (Get-NestedString $Endpoint "authorization.parameters.servicePrincipalID"),
        (Get-NestedString $Endpoint "data.servicePrincipalObjectId"),
        (Get-NestedString $Endpoint "authorization.parameters.servicePrincipalObjectId"),
        (Get-NestedString $Endpoint "authorization.parameters.servicePrincipalObjectID")
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and $candidate -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
            return $candidate
        }
    }

    return $null
}

function Get-AuthenticationType {
    param([object]$Endpoint)

    $scheme = Get-NestedString $Endpoint "authorization.scheme"

    $authType = Get-NestedString $Endpoint "data.authenticationType"

    if ($authType) {
        return $authType
    }

    if ($scheme) {
        return $scheme
    }

    return "Unknown"
}

function Get-GraphServicePrincipal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId
    )

    $select = "id,appId,displayName,accountEnabled,passwordCredentials,keyCredentials"
    $graphUri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId?`$select=$select"

    try {
        $raw = & az rest --method GET --url $graphUri 2>&1

        if ($LASTEXITCODE -ne 0) {
            $message = ($raw | Out-String).Trim()
            throw "az rest failed: $message"
        }

        $jsonText = ($raw | Out-String).Trim()

        if ([string]::IsNullOrWhiteSpace($jsonText)) {
            throw "Microsoft Graph returned an empty response."
        }

        return ($jsonText | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        throw $_
    }
}

function Get-CredentialRows {
    param(
        [object]$ServicePrincipal,
        [string]$AuthenticationType
    )

    $rows = @()

    $passwordCredentials = @()
    if ($null -ne $ServicePrincipal.passwordCredentials) {
        $passwordCredentials = @($ServicePrincipal.passwordCredentials)
    }

    $keyCredentials = @()
    if ($null -ne $ServicePrincipal.keyCredentials) {
        $keyCredentials = @($ServicePrincipal.keyCredentials)
    }

    foreach ($credential in $passwordCredentials) {
        $rows += [PSCustomObject]@{
            CredentialType       = "Client Secret"
            CredentialDisplayName = if ($credential.displayName) { $credential.displayName } else { "Unnamed secret" }
            CredentialKeyId      = [string]$credential.keyId
            CredentialStartDate  = [string]$credential.startDateTime
            CredentialExpirationDate = [string]$credential.endDateTime
            CredentialStatus     = "Unknown"
        }
    }

    foreach ($credential in $keyCredentials) {
        $rows += [PSCustomObject]@{
            CredentialType       = if ($credential.type) { [string]$credential.type } else { "Certificate/Key" }
            CredentialDisplayName = if ($credential.displayName) { $credential.displayName } else { "Unnamed certificate/key" }
            CredentialKeyId      = [string]$credential.keyId
            CredentialStartDate  = [string]$credential.startDateTime
            CredentialExpirationDate = [string]$credential.endDateTime
            CredentialStatus     = "Unknown"
        }
    }

    foreach ($row in $rows) {
        if ($row.CredentialExpirationDate) {
            try {
                $expiry = [DateTimeOffset]::Parse($row.CredentialExpirationDate)
                $now = [DateTimeOffset]::UtcNow

                if ($expiry -lt $now) {
                    $row.CredentialStatus = "Expired"
                }
                elseif ($expiry -le $now.AddDays(30)) {
                    $row.CredentialStatus = "Expires within 30 days"
                }
                elseif ($expiry -le $now.AddDays(90)) {
                    $row.CredentialStatus = "Expires within 90 days"
                }
                else {
                    $row.CredentialStatus = "Active"
                }

                if ($row.CredentialStartDate) {
                    $row.CredentialStartDate = [DateTimeOffset]::Parse($row.CredentialStartDate).ToString("yyyy-MM-ddTHH:mm:ssZ")
                }
                $row.CredentialExpirationDate = $expiry.ToString("yyyy-MM-ddTHH:mm:ssZ")
            }
            catch {
                # Leave original values if parsing fails.
            }
        }
    }

    if ($rows.Count -eq 0) {
        if ($AuthenticationType -match "Workload|Federated|OIDC") {
            return @(
                [PSCustomObject]@{
                    CredentialType = "Workload Identity Federation"
                    CredentialDisplayName = "Federated authentication"
                    CredentialKeyId = ""
                    CredentialStartDate = ""
                    CredentialExpirationDate = ""
                    CredentialStatus = "No client secret/certificate expiration"
                }
            )
        }

        return @(
            [PSCustomObject]@{
                CredentialType = "No password/key credential found"
                CredentialDisplayName = ""
                CredentialKeyId = ""
                CredentialStartDate = ""
                CredentialExpirationDate = ""
                CredentialStatus = "Not found / check Graph permissions"
            }
        )
    }

    return $rows
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

Write-Section "Azure DevOps Service Connection Inventory"

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    throw "Azure CLI 'az' was not found. Install Azure CLI and run 'az login' first."
}

if (-not (Test-Path $OutputFolder)) {
    New-Item -ItemType Directory -Path $OutputFolder -Force | Out-Null
}

$PatSecure = Read-Host "Enter Azure DevOps PAT" -AsSecureString
$PatPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PatSecure)

try {
    $Pat = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($PatPtr)
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($PatPtr)
}

if ([string]::IsNullOrWhiteSpace($Pat)) {
    throw "PAT cannot be empty."
}

$basic = [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes(":$Pat")
)

$adoHeaders = @{
    Authorization = "Basic $basic"
    Accept        = "application/json"
}

# Do not keep PAT around longer than necessary.
$Pat = $null

Write-Host "Organization: $Organization" -ForegroundColor Yellow
Write-Host "Output folder: $OutputFolder" -ForegroundColor Yellow

# Confirm Azure CLI login.
try {
    $account = az account show --output json | ConvertFrom-Json
    Write-Host "Azure CLI account: $($account.user.name)" -ForegroundColor Green
    Write-Host "Azure CLI tenant : $($account.tenantId)" -ForegroundColor Green
}
catch {
    throw "Azure CLI is not logged in. Run 'az login' and then run this script again."
}

Write-Host ""
Write-Host "Discovering Azure DevOps projects..." -ForegroundColor Yellow

$projects = @(Get-AdoProjects -Org $Organization -Headers $adoHeaders)

if ($projects.Count -eq 0) {
    throw "No Azure DevOps projects were returned. Check organization name and PAT permissions."
}

Write-Host "Projects discovered: $($projects.Count)" -ForegroundColor Green

$inventory = New-Object System.Collections.Generic.List[object]
$errors = New-Object System.Collections.Generic.List[object]

$projectNumber = 0

foreach ($project in $projects) {
    $projectNumber++

    $projectId = [string]$project.id
    $projectName = [string]$project.name

    Write-Host "[$projectNumber/$($projects.Count)] $projectName" -ForegroundColor Cyan

    try {
        $endpoints = @(Get-ServiceEndpoints `
            -Org $Organization `
            -ProjectId $projectId `
            -Headers $adoHeaders)

        foreach ($endpoint in $endpoints) {

            $endpointType = [string]$endpoint.type
            $endpointName = [string]$endpoint.name

            $isAzure = (
                $endpointType -match 'AzureRM|Azure Resource Manager|Azure'
            )

            $spId = Get-ServicePrincipalId -Endpoint $endpoint
            $authType = Get-AuthenticationType -Endpoint $endpoint

            # By default, focus on Azure service connections.
            if (-not $IncludeNonAzureServiceConnections -and -not $isAzure -and -not $spId) {
                continue
            }

            $createdByName = Get-NestedString $endpoint "createdBy.displayName"
            $createdByUniqueName = Get-NestedString $endpoint "createdBy.uniqueName"

            $createdDate = Get-StringProperty $endpoint @(
                "creationDate",
                "createdDate",
                "createdOn"
            )

            $subscriptionId = Get-NestedString $endpoint "data.subscriptionId"
            $subscriptionName = Get-NestedString $endpoint "data.subscriptionName"
            $tenantId = Get-NestedString $endpoint "data.tenantId"
            if (-not $tenantId) {
                $tenantId = Get-NestedString $endpoint "data.tenantid"
            }

            $authenticationType = Get-NestedString $endpoint "data.authenticationType"
            if (-not $authenticationType) {
                $authenticationType = $authType
            }

            $renewalProcess = switch -Regex ($authenticationType) {
                "spnKey|ServicePrincipal|ClientSecret" {
                    "Renew Entra ID client secret; update the ADO service connection with the new credential as required by the team's process."
                    break
                }
                "spnCertificate|Certificate" {
                    "Renew/replace the Entra ID certificate; update the ADO service connection as required by the team's process."
                    break
                }
                "Workload|Federated|OIDC" {
                    "Workload identity federation; no client-secret expiration. Review the federated identity configuration according to the team's process."
                    break
                }
                default {
                    "Review the authentication type and follow the team's approved renewal process."
                }
            }

            $base = [ordered]@{
                Organization = $Organization
                ProjectName = $projectName
                ProjectId = $projectId
                ServiceConnectionName = $endpointName
                ServiceConnectionId = [string]$endpoint.id
                ServiceConnectionType = $endpointType
                AuthenticationType = $authenticationType
                Owner = [string]$endpoint.owner
                IsShared = [string]$endpoint.isShared
                CreatedDate = $createdDate
                CreatedBy = $createdByName
                CreatedByUPN = $createdByUniqueName
                SubscriptionName = $subscriptionName
                SubscriptionId = $subscriptionId
                TenantId = $tenantId
                ServicePrincipalObjectId = $spId
                ApplicationId = ""
                ServicePrincipalDisplayName = ""
                AccountEnabled = ""
                CredentialType = ""
                CredentialDisplayName = ""
                CredentialKeyId = ""
                CredentialStartDate = ""
                CredentialExpirationDate = ""
                CredentialStatus = ""
                RenewalProcess = $renewalProcess
                InventoryStatus = "OK"
                Notes = ""
            }

            if ($spId) {
                try {
                    $sp = Get-GraphServicePrincipal -ServicePrincipalId $spId

                    $base.ApplicationId = [string]$sp.appId
                    $base.ServicePrincipalDisplayName = [string]$sp.displayName
                    $base.AccountEnabled = [string]$sp.accountEnabled

                    $credentialRows = @(Get-CredentialRows `
                        -ServicePrincipal $sp `
                        -AuthenticationType $authenticationType)

                    foreach ($credential in $credentialRows) {
                        $row = [ordered]@{}
                        foreach ($key in $base.Keys) {
                            $row[$key] = $base[$key]
                        }

                        $row.CredentialType = $credential.CredentialType
                        $row.CredentialDisplayName = $credential.CredentialDisplayName
                        $row.CredentialKeyId = $credential.CredentialKeyId
                        $row.CredentialStartDate = $credential.CredentialStartDate
                        $row.CredentialExpirationDate = $credential.CredentialExpirationDate
                        $row.CredentialStatus = $credential.CredentialStatus

                        if ($credential.CredentialStatus -eq "Not found / check Graph permissions") {
                            $row.InventoryStatus = "Graph credential lookup returned no credentials"
                        }

                        $inventory.Add([PSCustomObject]$row)
                    }
                }
                catch {
                    $base.InventoryStatus = "Graph lookup failed"
                    $base.Notes = $_.Exception.Message
                    $inventory.Add([PSCustomObject]$base)

                    $errors.Add([PSCustomObject]@{
                        ProjectName = $projectName
                        ProjectId = $projectId
                        ServiceConnectionName = $endpointName
                        ServiceConnectionId = [string]$endpoint.id
                        Error = $_.Exception.Message
                    })
                }
            }
            else {
                $base.InventoryStatus = "No service principal ID found"
                $base.Notes = "No Service Principal object ID was found in the endpoint data/authorization parameters."
                $inventory.Add([PSCustomObject]$base)
            }
        }
    }
    catch {
        $errors.Add([PSCustomObject]@{
            ProjectName = $projectName
            ProjectId = $projectId
            ServiceConnectionName = ""
            ServiceConnectionId = ""
            Error = $_.Exception.Message
        })

        Write-Warning "Could not read service connections from '$projectName': $($_.Exception.Message)"
    }
}

$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

$inventoryPath = Join-Path $OutputFolder "ADO-ServiceConnection-Inventory-$timestamp.csv"
$errorPath = Join-Path $OutputFolder "ADO-ServiceConnection-Inventory-Errors-$timestamp.csv"

$inventory |
    Export-Csv -Path $inventoryPath -NoTypeInformation -Encoding UTF8

$errors |
    Export-Csv -Path $errorPath -NoTypeInformation -Encoding UTF8

Write-Section "Inventory completed"

Write-Host "Organization              : $Organization"
Write-Host "Projects scanned          : $($projects.Count)"
Write-Host "Inventory rows            : $($inventory.Count)"
Write-Host "Project/Graph errors      : $($errors.Count)"
Write-Host ""
Write-Host "Inventory CSV:" -ForegroundColor Green
Write-Host $inventoryPath -ForegroundColor Green
Write-Host ""
Write-Host "Errors CSV:" -ForegroundColor Yellow
Write-Host $errorPath -ForegroundColor Yellow
Write-Host ""
Write-Host "Important: no client-secret or certificate secret values are exported." -ForegroundColor Cyan
