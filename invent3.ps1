#requires -Version 5.1
<#
.SYNOPSIS
    Azure DevOps Service Connection Inventory

.DESCRIPTION
    Reads every Azure DevOps project and every service connection in each project.
    It does NOT read or export secrets, PATs, tokens, or certificate private keys.

    Important:
      - Azure DevOps Service Endpoint API does not expose the service-connection
        creation date as a normal endpoint property.
      - For Azure AD/service-principal based connections, Microsoft Graph is used
        through the existing "az login" session to get application and credential
        dates.
      - CredentialCreatedDate is the Graph credential startDateTime. It is NOT
        the creation date of the Azure DevOps service-connection record.
      - CredentialExpiration is the password/certificate endDateTime.
      - The script only returns one inventory row per Azure DevOps service connection.

    Requirements:
      1. Windows PowerShell 5.1 or PowerShell 7+
      2. Azure CLI installed
      3. Azure DevOps PAT with permission to read projects and service connections
      4. "az login" completed in the same account/session when Graph credential
         information is required.
      5. Your Entra account must have sufficient Microsoft Graph permissions.
         If your organization requires PIM, activate the required role first.

    Run:
      .\ADO-ServiceConnection-Inventory-Final.ps1

    Optional:
      .\ADO-ServiceConnection-Inventory-Final.ps1 -Organization "humana" `
          -OutputCsv ".\ADO-ServiceConnection-Inventory.csv"
#>

[CmdletBinding()]
param(
    [string]$Organization = "humana",
    [string]$OutputCsv = ".\ADO-ServiceConnection-Inventory.csv"
)

$ErrorActionPreference = "Stop"

function Get-DevOpsHeaders {
    param(
        [Parameter(Mandatory)]
        [string]$Pat
    )

    $bytes = [System.Text.Encoding]::ASCII.GetBytes(":$Pat")
    $basic = [Convert]::ToBase64String($bytes)

    @{
        Authorization = "Basic $basic"
        Accept        = "application/json"
    }
}

function Invoke-DevOpsGet {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            return Invoke-RestMethod `
                -Uri $Uri `
                -Headers $Headers `
                -Method Get `
                -UseBasicParsing
        }
        catch {
            if ($attempt -eq 3) {
                throw
            }

            Start-Sleep -Seconds (2 * $attempt)
        }
    }
}

function Get-AllDevOpsProjects {
    param(
        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $allProjects = @()
    $continuationToken = $null

    do {
        $uri = "https://dev.azure.com/$Organization/_apis/projects?`$top=100&api-version=7.1"

        if ($continuationToken) {
            $encodedToken = [Uri]::EscapeDataString($continuationToken)
            $uri += "&continuationToken=$encodedToken"
        }

        $response = Invoke-WebRequest `
            -Uri $uri `
            -Headers $Headers `
            -Method Get `
            -UseBasicParsing

        $body = $response.Content | ConvertFrom-Json

        if ($body.value) {
            $allProjects += @($body.value)
        }

        $continuationToken = $null

        if ($response.Headers["x-ms-continuationtoken"]) {
            $continuationToken = [string]$response.Headers["x-ms-continuationtoken"]
        }
        elseif ($response.Headers["X-MS-ContinuationToken"]) {
            $continuationToken = [string]$response.Headers["X-MS-ContinuationToken"]
        }

    } while ($continuationToken)

    return $allProjects
}

function Get-ServiceConnections {
    param(
        [Parameter(Mandatory)]
        [string]$ProjectId,

        [Parameter(Mandatory)]
        [hashtable]$Headers
    )

    $uri = "https://dev.azure.com/$Organization/$ProjectId/_apis/serviceendpoint/endpoints?api-version=7.1"

    $response = Invoke-DevOpsGet `
        -Uri $uri `
        -Headers $Headers

    if ($null -eq $response.value) {
        return @()
    }

    return @($response.value)
}

function Test-AzureCli {
    $az = Get-Command az -ErrorAction SilentlyContinue
    return ($null -ne $az)
}

function Get-GraphApplicationByAppId {
    param(
        [Parameter(Mandatory)]
        [string]$AppId
    )

    if ([string]::IsNullOrWhiteSpace($AppId)) {
        return $null
    }

    if (-not (Test-AzureCli)) {
        return $null
    }

    $escapedAppId = $AppId.Replace("'", "''")
    $filter = [Uri]::EscapeDataString("appId eq '$escapedAppId'")

    $uri = "https://graph.microsoft.com/v1.0/applications?`$filter=$filter&`$select=id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials"

    try {
        # az rest obtains the Microsoft Graph access token from the current
        # Azure CLI login. No Graph token is printed or written to the CSV.
        $json = az rest `
            --method get `
            --url $uri `
            --resource "https://graph.microsoft.com/" `
            2>$null

        if ($LASTEXITCODE -ne 0) {
            return $null
        }

        $jsonText = ($json -join "`n")

        if ([string]::IsNullOrWhiteSpace($jsonText)) {
            return $null
        }

        $response = $jsonText | ConvertFrom-Json

        if ($response.value -and @($response.value).Count -gt 0) {
            return $response.value[0]
        }
    }
    catch {
        return $null
    }

    return $null
}

function Get-CredentialMetadata {
    param(
        [Parameter(Mandatory)]
        $Application
    )

    $credentials = @()

    if ($Application.passwordCredentials) {
        foreach ($credential in @($Application.passwordCredentials)) {
            $credentials += [pscustomobject]@{
                DisplayName = $credential.displayName
                Type        = "Client secret"
                StartDate   = $credential.startDateTime
                EndDate     = $credential.endDateTime
            }
        }
    }

    if ($Application.keyCredentials) {
        foreach ($credential in @($Application.keyCredentials)) {
            $credentials += [pscustomobject]@{
                DisplayName = $credential.displayName
                Type        = "Certificate"
                StartDate   = $credential.startDateTime
                EndDate     = $credential.endDateTime
            }
        }
    }

    if ($credentials.Count -eq 0) {
        return [pscustomobject]@{
            CredentialDisplayName = "No password/certificate credential exposed"
            CredentialType        = "None"
            CredentialCreatedDate = ""
            CredentialExpiration  = ""
            CredentialStatus      = "No credential exposed by Graph"
        }
    }

    $ordered = $credentials | Sort-Object EndDate

    $names = (
        $ordered |
        ForEach-Object { $_.DisplayName } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    ) -join "; "

    $types = (
        $ordered |
        ForEach-Object { $_.Type } |
        Select-Object -Unique
    ) -join "; "

    $startDates = @(
        $ordered |
        Where-Object { $_.StartDate } |
        ForEach-Object { [datetime]$_.StartDate }
    )

    $endDates = @(
        $ordered |
        Where-Object { $_.EndDate } |
        ForEach-Object { [datetime]$_.EndDate }
    )

    $createdDate = ""

    if ($startDates.Count -gt 0) {
        $earliestStart = $startDates | Sort-Object | Select-Object -First 1
        $createdDate = $earliestStart.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
    }

    $expirationDate = ""

    if ($endDates.Count -gt 0) {
        $nearestEnd = $endDates | Sort-Object | Select-Object -First 1
        $expirationDate = $nearestEnd.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
    }

    $status = "Active/Unknown"

    if ($endDates.Count -gt 0) {
        $nearestEnd = $endDates | Sort-Object | Select-Object -First 1
        $nowUtc = (Get-Date).ToUniversalTime()

        if ($nearestEnd -lt $nowUtc) {
            $status = "Expired"
        }
        elseif ($nearestEnd -lt $nowUtc.AddDays(30)) {
            $status = "Expires within 30 days"
        }
        else {
            $status = "Valid"
        }
    }

    return [pscustomobject]@{
        CredentialDisplayName = $names
        CredentialType        = $types
        CredentialCreatedDate = $createdDate
        CredentialExpiration  = $expirationDate
        CredentialStatus      = $status
    }
}

function Get-ServicePrincipalAppId {
    param(
        [Parameter(Mandatory)]
        $Endpoint
    )

    $candidateNames = @(
        "serviceprincipalid",
        "servicePrincipalId",
        "appId",
        "applicationId"
    )

    if ($Endpoint.authorization -and $Endpoint.authorization.parameters) {
        foreach ($candidateName in $candidateNames) {
            $property = $Endpoint.authorization.parameters.PSObject.Properties |
                Where-Object { $_.Name -ieq $candidateName } |
                Select-Object -First 1

            if ($property -and $property.Value) {
                return [string]$property.Value
            }
        }
    }

    return ""
}

function Get-CreatedByFromEndpoint {
    param(
        [Parameter(Mandatory)]
        $Endpoint
    )

    if ($Endpoint.PSObject.Properties.Name -contains "createdBy") {
        if ($Endpoint.createdBy -is [string]) {
            return [string]$Endpoint.createdBy
        }

        if ($Endpoint.createdBy.uniqueName) {
            return [string]$Endpoint.createdBy.uniqueName
        }

        if ($Endpoint.createdBy.displayName) {
            return [string]$Endpoint.createdBy.displayName
        }
    }

    return "Not exposed"
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " Azure DevOps Service Connection Inventory" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Organization: $Organization"
Write-Host ""

$PatSecure = Read-Host "Enter Azure DevOps PAT" -AsSecureString
$plainPat = [System.Net.NetworkCredential]::new("", $PatSecure).Password

if ([string]::IsNullOrWhiteSpace($plainPat)) {
    throw "PAT cannot be empty."
}

$adoHeaders = Get-DevOpsHeaders -Pat $plainPat

Write-Host "Getting Azure DevOps projects..." -ForegroundColor Yellow

try {
    $projects = Get-AllDevOpsProjects -Headers $adoHeaders
}
catch {
    throw "Unable to retrieve Azure DevOps projects. $($_.Exception.Message)"
}

Write-Host "Projects found: $($projects.Count)" -ForegroundColor Green

Write-Host ""
Write-Host "Checking Azure CLI / Microsoft Graph access..." -ForegroundColor Yellow

$graphAvailable = $false

if (Test-AzureCli) {
    try {
        $null = az account show --output none 2>$null

        if ($LASTEXITCODE -eq 0) {
            $graphAvailable = $true
            Write-Host "Azure CLI login detected. Graph will use the current az login/PIM context." -ForegroundColor Green
        }
    }
    catch {
        $graphAvailable = $false
    }
}

if (-not $graphAvailable) {
    Write-Host "Azure CLI login is unavailable. Graph credential fields will be Not available." -ForegroundColor Yellow
}

$results = [System.Collections.Generic.List[object]]::new()
$projectErrors = [System.Collections.Generic.List[object]]::new()

$projectNumber = 0

foreach ($project in $projects) {
    $projectNumber++

    $percent = ($projectNumber / [math]::Max($projects.Count, 1)) * 100

    Write-Progress `
        -Activity "Reading Azure DevOps service connections" `
        -Status "$projectNumber / $($projects.Count): $($project.name)" `
        -PercentComplete $percent

    try {
        $endpoints = Get-ServiceConnections `
            -ProjectId $project.id `
            -Headers $adoHeaders
    }
    catch {
        $projectErrors.Add(
            [pscustomobject]@{
                ProjectId   = $project.id
                ProjectName = $project.name
                Error       = $_.Exception.Message
            }
        )

        continue
    }

    foreach ($endpoint in $endpoints) {
        $appId = Get-ServicePrincipalAppId -Endpoint $endpoint

        $credential = [pscustomobject]@{
            CredentialDisplayName = ""
            CredentialType        = ""
            CredentialCreatedDate = ""
            CredentialExpiration  = ""
            CredentialStatus      = "Not applicable"
        }

        $servicePrincipalCreatedDate = ""
        $graphStatus = "Not applicable"

        if ($graphAvailable -and $appId) {
            $application = Get-GraphApplicationByAppId -AppId $appId

            if ($application) {
                $graphStatus = "Found"

                if ($application.createdDateTime) {
                    $servicePrincipalCreatedDate =
                        ([datetime]$application.createdDateTime).
                        ToUniversalTime().
                        ToString("yyyy-MM-dd HH:mm:ss 'UTC'")
                }

                $credential = Get-CredentialMetadata -Application $application
            }
            else {
                $graphStatus = "Not found / no permission"

                $credential = [pscustomobject]@{
                    CredentialDisplayName = ""
                    CredentialType        = ""
                    CredentialCreatedDate = ""
                    CredentialExpiration  = ""
                    CredentialStatus      = "Graph lookup failed"
                }
            }
        }

        $results.Add(
            [pscustomobject]@{
                Organization                 = $Organization
                ProjectName                  = $project.name
                ServiceConnectionName        = $endpoint.name
                ServiceConnectionId          = $endpoint.id
                ServiceConnectionType        = $endpoint.type
                AppOrServicePrincipalId      = $appId
                CreatedBy                    = (Get-CreatedByFromEndpoint -Endpoint $endpoint)
                ServicePrincipalCreatedDate  = $servicePrincipalCreatedDate
                CredentialDisplayName        = $credential.CredentialDisplayName
                CredentialType               = $credential.CredentialType
                CredentialCreatedDate       = $credential.CredentialCreatedDate
                CredentialExpiration        = $credential.CredentialExpiration
                CredentialStatus             = $credential.CredentialStatus
                GraphLookupStatus            = $graphStatus
            }
        )
    }
}

Write-Progress -Activity "Reading Azure DevOps service connections" -Completed

$resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputCsv)

$results |
    Sort-Object ProjectName, ServiceConnectionName |
    Export-Csv `
        -Path $resolvedOutput `
        -NoTypeInformation `
        -Encoding UTF8

$errorCsv = Join-Path `
    -Path ([System.IO.Path]::GetDirectoryName($resolvedOutput)) `
    -ChildPath "ADO-ServiceConnection-Inventory-Errors.csv"

if ($projectErrors.Count -gt 0) {
    $projectErrors |
        Export-Csv `
            -Path $errorCsv `
            -NoTypeInformation `
            -Encoding UTF8
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Green
Write-Host " Inventory completed successfully"
Write-Host "==============================================" -ForegroundColor Green
Write-Host "Projects              : $($projects.Count)"
Write-Host "Service connections   : $($results.Count)"
Write-Host "Project errors        : $($projectErrors.Count)"
Write-Host ""
Write-Host "Inventory CSV:"
Write-Host $resolvedOutput -ForegroundColor Cyan

if ($projectErrors.Count -gt 0) {
    Write-Host ""
    Write-Host "Errors CSV:" -ForegroundColor Yellow
    Write-Host $errorCsv -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Notes:"
Write-Host "1. No secrets, PATs, tokens, or certificate private keys are exported."
Write-Host "2. Service connection creation date is not exposed by the normal ADO endpoint API."
Write-Host "3. ServicePrincipalCreatedDate comes from Microsoft Graph application.createdDateTime."
Write-Host "4. CredentialCreatedDate comes from Graph credential startDateTime."
Write-Host "5. CredentialExpiration comes from Graph credential endDateTime."
Write-Host "6. Some service connection types do not use an Azure AD application; their Graph fields will be Not applicable."
Write-Host ""
