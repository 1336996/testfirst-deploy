[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Organization,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\ADO-ServiceConnection-Inventory.csv"
)

$ErrorActionPreference = "Stop"
$ApiVersion = "7.2"

function Get-PatHeader {
    $securePat = Read-Host "Enter Azure DevOps PAT" -AsSecureString
    $pat = [System.Net.NetworkCredential]::new("", $securePat).Password

    if ([string]::IsNullOrWhiteSpace($pat)) {
        throw "PAT cannot be empty."
    }

    $encoded = [Convert]::ToBase64String(
        [Text.Encoding]::ASCII.GetBytes(":$pat")
    )

    return @{
        Authorization = "Basic $encoded"
        Accept        = "application/json"
    }
}

function Invoke-AdoGet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $response = Invoke-WebRequest `
                -Uri $Uri `
                -Headers $Headers `
                -Method Get `
                -UseBasicParsing

            if ([string]::IsNullOrWhiteSpace($response.Content)) {
                return $null
            }

            return @{
                Body    = ($response.Content | ConvertFrom-Json)
                Headers = $response.Headers
            }
        }
        catch {
            if ($attempt -eq 3) {
                throw
            }
            Start-Sleep -Seconds ($attempt * 2)
        }
    }
}

function Get-AllProjects {
    param(
        [string]$Organization,
        [hashtable]$Headers
    )

    $projects = New-Object System.Collections.Generic.List[object]
    $continuation = $null

    do {
        $uri = "https://dev.azure.com/$Organization/_apis/projects?api-version=$ApiVersion"

        if ($continuation) {
            $uri += "&continuationToken=" + [uri]::EscapeDataString($continuation)
        }

        $result = Invoke-AdoGet -Uri $uri -Headers $Headers

        foreach ($project in @($result.Body.value)) {
            $projects.Add($project)
        }

        $continuation = $null
        if ($result.Headers.ContainsKey("x-ms-continuationtoken")) {
            $continuation = [string]$result.Headers["x-ms-continuationtoken"]
        }
    }
    while ($continuation)

    return $projects
}

function Get-ServiceEndpoints {
    param(
        [string]$Organization,
        [string]$ProjectId,
        [hashtable]$Headers
    )

    $endpoints = New-Object System.Collections.Generic.List[object]
    $continuation = $null

    do {
        $uri = "https://dev.azure.com/$Organization/$ProjectId/_apis/serviceendpoint/endpoints?api-version=$ApiVersion"

        if ($continuation) {
            $uri += "&continuationToken=" + [uri]::EscapeDataString($continuation)
        }

        $result = Invoke-AdoGet -Uri $uri -Headers $Headers

        foreach ($endpoint in @($result.Body.value)) {
            $endpoints.Add($endpoint)
        }

        $continuation = $null
        if ($result.Headers.ContainsKey("x-ms-continuationtoken")) {
            $continuation = [string]$result.Headers["x-ms-continuationtoken"]
        }
    }
    while ($continuation)

    return $endpoints
}

function Get-PropertyValue {
    param(
        [object]$Object,
        [string[]]$Names
    )

    if ($null -eq $Object) {
        return $null
    }

    foreach ($name in $Names) {
        $property = $Object.PSObject.Properties[$name]
        if ($property -and $null -ne $property.Value -and "$($property.Value)" -ne "") {
            return $property.Value
        }
    }

    return $null
}

function Get-EndpointValue {
    param(
        [object]$Endpoint,
        [string[]]$Names
    )

    $value = Get-PropertyValue -Object $Endpoint.data -Names $Names
    if ($null -ne $value) {
        return $value
    }

    return Get-PropertyValue -Object $Endpoint.authorization.parameters -Names $Names
}

function Get-ServicePrincipalObjectId {
    param([object]$Endpoint)

    return Get-EndpointValue -Endpoint $Endpoint -Names @(
        "serviceprincipalid",
        "servicePrincipalId",
        "servicePrincipalObjectId",
        "serviceprincipalobjectid",
        "spObjectId"
    )
}

function Get-ApplicationId {
    param([object]$Endpoint)

    return Get-EndpointValue -Endpoint $Endpoint -Names @(
        "applicationId",
        "applicationid",
        "appId",
        "clientId"
    )
}

function Get-AuthenticationType {
    param([object]$Endpoint)

    $authType = Get-EndpointValue -Endpoint $Endpoint -Names @(
        "authenticationType"
    )

    if ($authType) {
        return [string]$authType
    }

    $scheme = $null
    if ($Endpoint.authorization) {
        $scheme = $Endpoint.authorization.scheme
    }

    if ($scheme) {
        return [string]$scheme
    }

    return ""
}

function Get-CredentialDetails {
    param(
        [string]$ServicePrincipalObjectId,
        [string]$TenantId,
        [hashtable]$GraphCache
    )

    if ([string]::IsNullOrWhiteSpace($ServicePrincipalObjectId)) {
        return @{
            DisplayName = ""
            ApplicationId = ""
            Expiration = ""
            CredentialType = ""
            RenewalProcess = "Not applicable - no service principal ID exposed by the service connection."
            Status = "Not available"
        }
    }

    if ($GraphCache.ContainsKey($ServicePrincipalObjectId)) {
        return $GraphCache[$ServicePrincipalObjectId]
    }

    try {
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            throw "Tenant ID is missing from the service connection."
        }

        $tokenJson = & az account get-access-token `
            --tenant $TenantId `
            --resource-type ms-graph `
            --output json 2>&1

        if ($LASTEXITCODE -ne 0) {
            throw (($tokenJson -join "`n").Trim())
        }

        $token = (($tokenJson -join "`n") | ConvertFrom-Json).accessToken

        if ([string]::IsNullOrWhiteSpace($token)) {
            throw "Azure CLI did not return a Microsoft Graph access token."
        }

        $select = [uri]::EscapeDataString(
            '$select=id,appId,displayName,passwordCredentials,keyCredentials'
        )

        $uri = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalObjectId?$select"

        $graphHeaders = @{
            Authorization = "Bearer $token"
            Accept        = "application/json"
        }

        $sp = (Invoke-WebRequest `
            -Uri $uri `
            -Headers $graphHeaders `
            -Method Get `
            -UseBasicParsing).Content | ConvertFrom-Json

        $credentials = @()

        foreach ($credential in @($sp.passwordCredentials)) {
            if ($credential.endDateTime) {
                $credentials += [pscustomobject]@{
                    Type        = "Client Secret"
                    DisplayName = [string]$credential.displayName
                    Start       = [string]$credential.startDateTime
                    End         = [string]$credential.endDateTime
                }
            }
        }

        foreach ($credential in @($sp.keyCredentials)) {
            if ($credential.endDateTime) {
                $credentials += [pscustomobject]@{
                    Type        = "Certificate/Key"
                    DisplayName = [string]$credential.displayName
                    Start       = [string]$credential.startDateTime
                    End         = [string]$credential.endDateTime
                }
            }
        }

        $now = [datetime]::UtcNow

        # If several credentials exist, use the earliest-expiring currently
        # active credential. This is the most useful value for renewal tracking.
        $activeCredentials = @(
            $credentials | Where-Object {
                ([datetime]$_.Start -le $now) -and
                ([datetime]$_.End -gt $now)
            } | Sort-Object { [datetime]$_.End }
        )

        if ($activeCredentials.Count -gt 0) {
            $selected = $activeCredentials[0]
            $expiry = [datetime]$selected.End

            if ($expiry -le $now.AddDays(30)) {
                $status = "Expires within 30 days"
            }
            elseif ($expiry -le $now.AddDays(90)) {
                $status = "Expires within 90 days"
            }
            else {
                $status = "Active"
            }

            $renewal = "Renew the $($selected.Type) in Microsoft Entra ID before the expiry date; update/rotate the Azure DevOps service connection if the credential changes."
        }
        elseif ($credentials.Count -gt 0) {
            $selected = $credentials |
                Sort-Object { [datetime]$_.End } -Descending |
                Select-Object -First 1

            $expiry = [datetime]$selected.End
            $status = "Expired"
            $renewal = "Create/renew a valid $($selected.Type) in Microsoft Entra ID and update/rotate the Azure DevOps service connection."
        }
        else {
            $expiry = ""
            $status = "No secret/certificate expiry"
            $authScheme = [string]$null
            if ($ServicePrincipalObjectId) {
                $authScheme = "Service Principal"
            }

            $renewal = "No client-secret/certificate found. Check whether the connection uses workload identity federation or another non-secret authentication method."
        }

        $details = @{
            DisplayName      = [string]$sp.displayName
            ApplicationId    = [string]$sp.appId
            Expiration       = [string]$expiry
            CredentialType   = if ($selected) { $selected.Type } else { "" }
            RenewalProcess   = $renewal
            Status           = $status
        }

        $GraphCache[$ServicePrincipalObjectId] = $details
        return $details
    }
    catch {
        $details = @{
            DisplayName      = ""
            ApplicationId    = ""
            Expiration       = ""
            CredentialType   = ""
            RenewalProcess   = "Graph lookup failed: $($_.Exception.Message)"
            Status           = "Graph lookup failed"
        }

        $GraphCache[$ServicePrincipalObjectId] = $details
        return $details
    }
}

# -----------------------------
# Main
# -----------------------------

Write-Host ""
Write-Host "Azure DevOps Service Connection Inventory" -ForegroundColor Cyan
Write-Host "Organization: $Organization"
Write-Host ""

$headers = Get-PatHeader

Write-Host "Getting projects..." -ForegroundColor Yellow
$projects = Get-AllProjects -Organization $Organization -Headers $headers

Write-Host "Projects found: $($projects.Count)" -ForegroundColor Green

$inventory = @{}
$graphCache = @{}
$errors = New-Object System.Collections.Generic.List[object]

$projectNumber = 0

foreach ($project in $projects) {
    $projectNumber++
    Write-Progress `
        -Activity "Scanning Azure DevOps projects" `
        -Status "$($projectNumber) / $($projects.Count): $($project.name)" `
        -PercentComplete (($projectNumber / $projects.Count) * 100)

    try {
        $endpoints = Get-ServiceEndpoints `
            -Organization $Organization `
            -ProjectId $project.id `
            -Headers $headers
    }
    catch {
        $errors.Add([pscustomobject]@{
            Project = $project.name
            Error   = $_.Exception.Message
        })
        continue
    }

    foreach ($endpoint in $endpoints) {

        # One inventory row per unique service connection.
        # If the same endpoint is shared with multiple projects, projects are
        # combined into one cell instead of creating duplicate rows.
        $key = [string]$endpoint.id

        if (-not $inventory.ContainsKey($key)) {
            $servicePrincipalId = [string](Get-ServicePrincipalObjectId -Endpoint $endpoint)

            $tenantId = [string](Get-EndpointValue -Endpoint $endpoint -Names @(
                "tenantid",
                "tenantId"
            ))

            $subscriptionId = [string](Get-EndpointValue -Endpoint $endpoint -Names @(
                "subscriptionId",
                "subscriptionid"
            ))

            $subscriptionName = [string](Get-EndpointValue -Endpoint $endpoint -Names @(
                "subscriptionName",
                "subscriptionname"
            ))

            $applicationId = [string](Get-ApplicationId -Endpoint $endpoint)

            $credential = Get-CredentialDetails `
                -ServicePrincipalObjectId $servicePrincipalId `
                -TenantId $tenantId `
                -GraphCache $graphCache

            $createdBy = ""
            $createdByUpn = ""

            if ($endpoint.createdBy) {
                $createdBy = [string]$endpoint.createdBy.displayName
                $createdByUpn = [string]$endpoint.createdBy.uniqueName
            }

            $creationDate = ""
            if ($endpoint.creationDate) {
                $creationDate = ([datetime]$endpoint.creationDate).ToString("yyyy-MM-dd HH:mm:ss")
            }

            $projectNames = New-Object System.Collections.Generic.List[string]

            if ($endpoint.serviceEndpointProjectReferences) {
                foreach ($reference in @($endpoint.serviceEndpointProjectReferences)) {
                    if ($reference.projectReference.name) {
                        $projectNames.Add([string]$reference.projectReference.name)
                    }
                }
            }

            if (-not $projectNames.Contains([string]$project.name)) {
                $projectNames.Add([string]$project.name)
            }

            $inventory[$key] = [pscustomobject]@{
                Projects                  = (($projectNames | Sort-Object -Unique) -join "; ")
                ServiceConnection         = [string]$endpoint.name
                Type                      = [string]$endpoint.type
                Authentication            = Get-AuthenticationType -Endpoint $endpoint
                CreatedDate               = $creationDate
                CreatedBy                 = $createdBy
                CreatedByUPN              = $createdByUpn
                Owner                     = [string]$endpoint.owner
                ServicePrincipalObjectId  = $servicePrincipalId
                ServicePrincipal          = $credential.DisplayName
                ApplicationId             = if ($credential.ApplicationId) { $credential.ApplicationId } else { $applicationId }
                Subscription              = $subscriptionName
                SubscriptionId             = $subscriptionId
                TenantId                  = $tenantId
                CredentialType            = $credential.CredentialType
                CredentialExpiration      = $credential.Expiration
                CredentialStatus          = $credential.Status
                RenewalProcess            = $credential.RenewalProcess
            }
        }
        else {
            # Add another project to an existing shared service connection.
            $existing = $inventory[$key]
            $names = @($existing.Projects -split "; " | Where-Object { $_ })

            if (-not $names.Contains([string]$project.name)) {
                $names += [string]$project.name
                $existing.Projects = (($names | Sort-Object -Unique) -join "; ")
            }
        }
    }
}

Write-Progress -Activity "Scanning Azure DevOps projects" -Completed

$finalRows = @($inventory.Values | Sort-Object ServiceConnection, Projects)

$outputFullPath = [System.IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $outputFullPath

if (-not (Test-Path $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

$finalRows | Export-Csv -Path $outputFullPath -NoTypeInformation -Encoding UTF8

if ($errors.Count -gt 0) {
    $errorPath = [System.IO.Path]::Combine(
        $outputDirectory,
        "ADO-ServiceConnection-Inventory-Errors.csv"
    )
    $errors | Export-Csv -Path $errorPath -NoTypeInformation -Encoding UTF8
}

Write-Host ""
Write-Host "Inventory completed." -ForegroundColor Green
Write-Host "Projects scanned       : $($projects.Count)"
Write-Host "Unique service connections: $($finalRows.Count)"
Write-Host "Project/API errors     : $($errors.Count)"
Write-Host "CSV                   : $outputFullPath"

if ($errors.Count -gt 0) {
    Write-Host "Error CSV              : $errorPath" -ForegroundColor Yellow
}

Write-Host ""
