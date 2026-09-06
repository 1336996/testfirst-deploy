#requires -Version 5.1
<#
.SYNOPSIS
    Azure DevOps Service Connection / Azure credential inventory.

.DESCRIPTION
    Scans every Azure DevOps project visible to the PAT and inventories
    Azure service connections.

    For Azure service connections with a Service Principal ID:
      - Microsoft Graph is used through Azure CLI to read credential metadata.
      - Client secret expiration is read from passwordCredentials.
      - Certificate expiration is read from keyCredentials.
      - Workload Identity Federation and Managed Identity are reported
        without inventing a secret/certificate expiration.

    Azure DevOps Audit Log is queried once for the last 90 days and used
    to find service-connection creation events. Azure DevOps audit data
    is normally retained for 90 days, so older CreatedDate values may
    legitimately be unavailable.

    No service-connection secrets, tokens, passwords, private keys, or
    authorization.parameters are exported.

.NOTES
    Azure DevOps REST API: 7.1
    Azure DevOps Audit API: 7.1-preview.1
    Microsoft Graph: v1.0

    PAT:
      - Project: Read
      - Service Connections: Read
      - View audit log / vso.auditlog if CreatedDate is required

    Azure CLI:
      - Must be installed.
      - Run "az login" before this script.
      - The signed-in Azure identity must be allowed to read the
        service principals in Microsoft Graph.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Organization,

    [string]$OutputFile = ".\ADO-ServiceConnection-Inventory.csv",

    [string]$ErrorFile = ".\ADO-ServiceConnection-Inventory-Errors.csv",

    [ValidateRange(1,90)]
    [int]$AuditDays = 90
)

$ErrorActionPreference = "Stop"
$AdoApiVersion = "7.1"
$AuditApiVersion = "7.1-preview.1"

# ------------------------------------------------------------
# PAT
# ------------------------------------------------------------

$PAT = $env:ADO_PAT

if ([string]::IsNullOrWhiteSpace($PAT)) {
    $SecurePAT = Read-Host "Enter Azure DevOps PAT" -AsSecureString
    $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePAT)

    try {
        $PAT = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($BSTR)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
    }
}

if ([string]::IsNullOrWhiteSpace($PAT)) {
    throw "A PAT is required."
}

$EncodedPAT = [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes(":$PAT")
)

$Headers = @{
    Authorization = "Basic $EncodedPAT"
    Accept        = "application/json"
}

# ------------------------------------------------------------
# Generic Azure DevOps GET
# ------------------------------------------------------------

function Invoke-AdoGet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $maxAttempts = 4

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            $response = Invoke-WebRequest `
                -Uri $Uri `
                -Headers $Headers `
                -Method Get `
                -UseBasicParsing

            $content = [string]$response.Content

            if ([string]::IsNullOrWhiteSpace($content)) {
                throw "Azure DevOps returned an empty response."
            }

            try {
                $body = $content | ConvertFrom-Json
            }
            catch {
                $preview = $content.Substring(
                    0,
                    [Math]::Min(300, $content.Length)
                )

                throw "Azure DevOps returned non-JSON content. Response starts with: $preview"
            }

            return @{
                Body    = $body
                Headers = $response.Headers
            }
        }
        catch {
            if ($attempt -eq $maxAttempts) {
                throw "GET failed: $Uri`n$($_.Exception.Message)"
            }

            $statusCode = 0

            try {
                if ($null -ne $_.Exception.Response) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
            }
            catch {
                $statusCode = 0
            }

            if (($statusCode -eq 429) -or
                (($statusCode -ge 500) -and ($statusCode -lt 600))) {

                $delay = [int][Math]::Pow(2, $attempt)
                Write-Warning "HTTP $statusCode. Retrying in $delay seconds..."
                Start-Sleep -Seconds $delay
            }
            else {
                throw
            }
        }
    }
}

# ------------------------------------------------------------
# Safe property helper
# ------------------------------------------------------------

function Get-PropertyValue {
    param(
        $Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($null -eq $Object) {
        return ""
    }

    $property = $Object.PSObject.Properties[$Name]

    if ($null -eq $property -or $null -eq $property.Value) {
        return ""
    }

    return [string]$property.Value
}

# ------------------------------------------------------------
# Azure CLI / Graph
# ------------------------------------------------------------

function Test-AzureCli {
    try {
        $null = Get-Command az -ErrorAction Stop
    }
    catch {
        throw "Azure CLI 'az' was not found. Install Azure CLI before running this script."
    }

    try {
        $accountJson = & az account show --output json 2>$null

        if ($LASTEXITCODE -ne 0 -or
            [string]::IsNullOrWhiteSpace(($accountJson -join ""))) {
            throw "Azure CLI is not logged in."
        }

        $account = ($accountJson -join "`n") | ConvertFrom-Json

        Write-Host "Azure CLI tenant : $($account.tenantId)"
        Write-Host "Azure CLI account: $($account.user.name)"
        Write-Host ""
    }
    catch {
        throw "Azure CLI is not logged in. Run 'az login' first, then run this script again."
    }
}

function Invoke-GraphServicePrincipal {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalId,

        [Parameter(Mandatory = $true)]
        [string]$TenantId
    )

    $select = [uri]::EscapeDataString(
        '$select=id,appId,displayName,passwordCredentials,keyCredentials'
    )

    $uri =
        "https://graph.microsoft.com/v1.0/servicePrincipals/" +
        "$ServicePrincipalId?$select"

    try {
        # Request a Microsoft Graph access token for the tenant that
        # owns the service principal. This avoids depending on the
        # currently selected Azure subscription.
        $tokenJson = & az account get-access-token `
            --tenant $TenantId `
            --resource-type ms-graph `
            --output json 2>&1

        if ($LASTEXITCODE -ne 0) {
            throw (($tokenJson -join "`n").Trim())
        }

        $tokenText = ($tokenJson -join "`n")

        if ([string]::IsNullOrWhiteSpace($tokenText)) {
            throw "Azure CLI returned an empty Graph access-token response."
        }

        $tokenObject = $tokenText | ConvertFrom-Json
        $accessToken = [string]$tokenObject.accessToken

        if ([string]::IsNullOrWhiteSpace($accessToken)) {
            throw "Azure CLI did not return a Microsoft Graph access token."
        }

        $graphHeaders = @{
            Authorization = "Bearer $accessToken"
            Accept        = "application/json"
        }

        $response = Invoke-WebRequest `
            -Uri $uri `
            -Headers $graphHeaders `
            -Method Get `
            -UseBasicParsing

        $jsonText = [string]$response.Content

        if ([string]::IsNullOrWhiteSpace($jsonText)) {
            throw "Microsoft Graph returned an empty response."
        }

        return $jsonText | ConvertFrom-Json
    }
    catch {
        throw "Microsoft Graph lookup failed for Service Principal '$ServicePrincipalId' in tenant '$TenantId': $($_.Exception.Message)"
    }
}

# ------------------------------------------------------------
# Graph credential extraction
# ------------------------------------------------------------

function Get-GraphCredentialInfo {
    param(
        [Parameter(Mandatory = $true)]
        $ServicePrincipal,

        [string]$PreferredType = ""
    )

    $now = [DateTime]::UtcNow

    $allSecrets = @($ServicePrincipal.passwordCredentials)
    $allKeys = @($ServicePrincipal.keyCredentials)

    # Match the credential family used by the ADO connection when
    # ADO exposes authenticationType. Otherwise inspect both.
    $secrets = $allSecrets
    $keys = $allKeys

    if ($PreferredType -eq "Secret") {
        $keys = @()
    }
    elseif ($PreferredType -eq "Certificate") {
        $secrets = @()
    }

    $allCredentials = @()

    foreach ($secret in $secrets) {
        $allCredentials += [PSCustomObject]@{
            Type        = "Client Secret"
            DisplayName = [string]$secret.displayName
            StartDate   = [string]$secret.startDateTime
            EndDate     = [string]$secret.endDateTime
        }
    }

    foreach ($key in $keys) {
        $allCredentials += [PSCustomObject]@{
            Type        = "Certificate"
            DisplayName = [string]$key.displayName
            StartDate   = [string]$key.startDateTime
            EndDate     = [string]$key.endDateTime
        }
    }

    $parsedCredentials = @()

    foreach ($credential in $allCredentials) {
        $end = $null

        try {
            $end = [DateTime]::Parse(
                $credential.EndDate,
                [Globalization.CultureInfo]::InvariantCulture,
                [Globalization.DateTimeStyles]::AssumeUniversal
            ).ToUniversalTime()
        }
        catch {
            $end = $null
        }

        if ($null -ne $end) {
            $parsedCredentials += [PSCustomObject]@{
                Credential = $credential
                EndDate    = $end
            }
        }
    }

    # Prefer the credential that is currently valid and expires next.
    $nextCredential = @(
        $parsedCredentials |
        Where-Object {
            $_.EndDate -gt $now
        } |
        Sort-Object EndDate
    )[0]

    # If none are valid, return the most recently expiring credential
    # so the inventory can still show that the SP has expired metadata.
    if ($null -eq $nextCredential) {
        $nextCredential = @(
            $parsedCredentials |
            Sort-Object EndDate -Descending
        )[0]
    }

    $credentialType = "None"

    if ($allCredentials.Count -gt 0) {
        $types = @(
            $allCredentials |
            Select-Object -ExpandProperty Type -Unique
        )

        $credentialType = $types -join " + "
    }

    $expirationDate = ""
    $startDate = ""
    $displayName = ""

    if ($null -ne $nextCredential) {
        $expirationDate =
            [string]$nextCredential.Credential.EndDate

        $startDate =
            [string]$nextCredential.Credential.StartDate

        $displayName =
            [string]$nextCredential.Credential.DisplayName
    }

    $status = "No credential metadata"

    if ($allCredentials.Count -eq 0) {
        $status = "No client secret/certificate found"
    }
    elseif ($null -eq $nextCredential) {
        $status = "Credential exists; expiration could not be parsed"
    }
    else {
        if ($nextCredential.EndDate -le $now) {
            $status = "Expired"
        }
        elseif ($nextCredential.EndDate -le $now.AddDays(30)) {
            $status = "Expires within 30 days"
        }
        elseif ($nextCredential.EndDate -le $now.AddDays(90)) {
            $status = "Expires within 90 days"
        }
        else {
            $status = "Valid"
        }
    }

    $allExpirationDates = @(
        $allCredentials |
        Where-Object {
            -not [string]::IsNullOrWhiteSpace($_.EndDate)
        } |
        ForEach-Object {
            "$($_.Type): $($_.EndDate)"
        }
    ) -join "; "

    return [PSCustomObject]@{
        CredentialType        = $credentialType
        CredentialDisplayName = $displayName
        CredentialStartDate   = $startDate
        ExpirationDate        = $expirationDate
        CredentialStatus      = $status
        AllCredentialExpiries = $allExpirationDates
        GraphDisplayName      = [string]$ServicePrincipal.displayName
        GraphAppId            = [string]$ServicePrincipal.appId
    }
}

# ------------------------------------------------------------
# Audit log
# ------------------------------------------------------------

function Get-AuditEntries {
    param(
        [Parameter(Mandatory = $true)]
        [int]$Days
    )

    $startTime = [DateTime]::UtcNow.AddDays(-$Days)
    $endTime = [DateTime]::UtcNow

    $startText = $startTime.ToString(
        "yyyy-MM-ddTHH:mm:ssZ",
        [Globalization.CultureInfo]::InvariantCulture
    )

    $endText = $endTime.ToString(
        "yyyy-MM-ddTHH:mm:ssZ",
        [Globalization.CultureInfo]::InvariantCulture
    )

    $entries = New-Object System.Collections.Generic.List[object]
    $continuation = $null

    do {
        $uri =
            "https://auditservice.dev.azure.com/$Organization/" +
            "_apis/audit/auditlog" +
            "?startTime=$([uri]::EscapeDataString($startText))" +
            "&endTime=$([uri]::EscapeDataString($endText))" +
            "&batchSize=1000" +
            "&skipAggregation=true" +
            "&api-version=$AuditApiVersion"

        if (-not [string]::IsNullOrWhiteSpace($continuation)) {
            $uri +=
                "&continuationToken=" +
                [uri]::EscapeDataString($continuation)
        }

        Write-Host "Retrieving Azure DevOps audit-log page..."

        $response = Invoke-AdoGet -Uri $uri
        $result = $response.Body.value

        if ($null -ne $result.decoratedAuditLogEntries) {
            foreach ($entry in @($result.decoratedAuditLogEntries)) {
                $entries.Add($entry)
            }
        }

        $continuation = [string]$result.continuationToken

        if ($result.hasMore -ne $true) {
            $continuation = ""
        }

    } while (-not [string]::IsNullOrWhiteSpace($continuation))

    return @($entries)
}

function Find-ServiceConnectionCreationEvent {
    param(
        [Parameter(Mandatory = $true)]
        $AuditEntries,

        [Parameter(Mandatory = $true)]
        [string]$EndpointId,

        [Parameter(Mandatory = $true)]
        [string]$EndpointName,

        [Parameter(Mandatory = $true)]
        [string]$ProjectId
    )

    $creationActions = @(
        "Library.ServiceConnectionCreated",
        "Library.ServiceConnectionCreatedForMultipleProjects"
    )

    $candidates = New-Object System.Collections.Generic.List[object]

    foreach ($entry in @($AuditEntries)) {

        if ($creationActions -notcontains [string]$entry.actionId) {
            continue
        }

        $score = 0
        $dataJson = ""

        try {
            if ($null -ne $entry.data) {
                $dataJson =
                    $entry.data |
                    ConvertTo-Json -Depth 20 -Compress
            }
        }
        catch {
            $dataJson = ""
        }

        # Strongest match: endpoint/service-connection ID.
        if (-not [string]::IsNullOrWhiteSpace($EndpointId) -and
            $dataJson -match [regex]::Escape($EndpointId)) {
            $score += 100
        }

        # Next strongest: project ID.
        if (-not [string]::IsNullOrWhiteSpace($ProjectId)) {

            if ([string]$entry.projectId -eq $ProjectId) {
                $score += 40
            }
            elseif ($dataJson -match [regex]::Escape($ProjectId)) {
                $score += 30
            }
        }

        # Name is only a supporting signal.
        if (-not [string]::IsNullOrWhiteSpace($EndpointName)) {

            if ([string]$entry.details -like "*$EndpointName*") {
                $score += 20
            }
            elseif ($dataJson -like "*$EndpointName*") {
                $score += 10
            }
        }

        # Require at least a project+name match when the endpoint ID
        # is not present in the audit data. This avoids matching an
        # unrelated connection with the same name.
        $hasEndpointIdMatch =
            (-not [string]::IsNullOrWhiteSpace($EndpointId) -and
             $dataJson -match [regex]::Escape($EndpointId))

        $hasProjectMatch =
            (([string]$entry.projectId -eq $ProjectId) -or
             ($dataJson -match [regex]::Escape($ProjectId)))

        $hasNameMatch =
            (([string]$entry.details -like "*$EndpointName*") -or
             ($dataJson -like "*$EndpointName*"))

        if (-not $hasEndpointIdMatch -and
            -not ($hasProjectMatch -and $hasNameMatch)) {
            continue
        }

        if ($score -gt 0) {
            $candidates.Add(
                [PSCustomObject]@{
                    Score = $score
                    Entry = $entry
                }
            )
        }
    }

    if ($candidates.Count -eq 0) {
        return $null
    }

    return @(
        $candidates |
        Sort-Object `
            @{Expression = { $_.Score }; Descending = $true}, `
            @{Expression = {
                try {
                    [DateTime]::Parse(
                        [string]$_.Entry.timestamp,
                        [Globalization.CultureInfo]::InvariantCulture,
                        [Globalization.DateTimeStyles]::AssumeUniversal
                    )
                }
                catch {
                    [DateTime]::MinValue
                }
            }; Descending = $true}
    )[0].Entry
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================"
Write-Host "Azure DevOps Service Connection Credential Inventory"
Write-Host "============================================================"
Write-Host ""
Write-Host "Organization: $Organization"
Write-Host ""

Test-AzureCli

# ------------------------------------------------------------
# Get ALL projects
# ------------------------------------------------------------

$Projects = @()
$ContinuationToken = $null

do {
    $ProjectUri =
        "https://dev.azure.com/$Organization/_apis/projects" +
        "?`$top=1000" +
        "&api-version=$AdoApiVersion"

    if (-not [string]::IsNullOrWhiteSpace($ContinuationToken)) {
        $ProjectUri +=
            "&continuationToken=" +
            [uri]::EscapeDataString($ContinuationToken)
    }

    Write-Host "Retrieving Azure DevOps project page..."

    $ProjectResponse = Invoke-AdoGet -Uri $ProjectUri

    if ($null -ne $ProjectResponse.Body.value) {
        $Projects += @($ProjectResponse.Body.value)
    }

    $ContinuationToken = ""

    if ($null -ne $ProjectResponse.Headers) {

        $ContinuationToken =
            $ProjectResponse.Headers["x-ms-continuationtoken"]

        if ($ContinuationToken -is [array]) {
            $ContinuationToken = $ContinuationToken[0]
        }

        if ([string]::IsNullOrWhiteSpace($ContinuationToken)) {

            $ContinuationToken =
                $ProjectResponse.Headers["X-MS-ContinuationToken"]

            if ($ContinuationToken -is [array]) {
                $ContinuationToken = $ContinuationToken[0]
            }
        }
    }

} while (-not [string]::IsNullOrWhiteSpace($ContinuationToken))

Write-Host ""
Write-Host "Total projects discovered: $($Projects.Count)"
Write-Host ""

if ($Projects.Count -eq 0) {
    throw "No projects were returned. Check organization name and PAT permissions."
}

# ------------------------------------------------------------
# Audit log - one organization-level download
# ------------------------------------------------------------

$AuditEntries = @()

try {
    Write-Host "Retrieving Azure DevOps audit events from the last $AuditDays days..."
    $AuditEntries = Get-AuditEntries -Days $AuditDays
    Write-Host "Audit events retrieved: $($AuditEntries.Count)"
}
catch {
    Write-Warning `
        "Audit log could not be read. CreatedDate will be unavailable: $($_.Exception.Message)"
}

# ------------------------------------------------------------
# Inventory
# ------------------------------------------------------------

$Inventory = New-Object System.Collections.Generic.List[object]
$Errors = New-Object System.Collections.Generic.List[object]

# Service connection ID -> inventory row
$ByEndpointId = @{}

# Service Principal ID -> raw Graph object
$GraphCache = @{}

$ProjectNumber = 0

foreach ($Project in $Projects) {

    $ProjectNumber++

    $percent = [int](($ProjectNumber / $Projects.Count) * 100)

    Write-Progress `
        -Activity "Scanning Azure DevOps projects" `
        -Status "$($Project.name)" `
        -PercentComplete $percent

    Write-Host "[$ProjectNumber/$($Projects.Count)] $($Project.name)"

    try {

        $EndpointUri =
            "https://dev.azure.com/$Organization/" +
            "$($Project.id)/_apis/serviceendpoint/endpoints" +
            "?api-version=$AdoApiVersion"

        $EndpointResponse = Invoke-AdoGet -Uri $EndpointUri

        foreach ($Endpoint in @($EndpointResponse.Body.value)) {

            $EndpointId =
                Get-PropertyValue `
                    -Object $Endpoint `
                    -Name "id"

            if ([string]::IsNullOrWhiteSpace($EndpointId)) {
                continue
            }

            $EndpointName =
                Get-PropertyValue `
                    -Object $Endpoint `
                    -Name "name"

            $EndpointType =
                Get-PropertyValue `
                    -Object $Endpoint `
                    -Name "type"

            # ----------------------------------------------------
            # Only Azure service connections are in scope.
            # ----------------------------------------------------

            $IsAzureServiceConnection = $false

            if ($EndpointType -like "*Azure*" -or
                $EndpointType -like "*AzureRM*") {
                $IsAzureServiceConnection = $true
            }

            if (-not $IsAzureServiceConnection) {
                continue
            }

            # ----------------------------------------------------
            # Basic endpoint metadata
            # ----------------------------------------------------

            $CreatedByName = ""
            $CreatedByUniqueName = ""
            $CreatedById = ""

            if ($null -ne $Endpoint.createdBy) {

                $CreatedByName =
                    Get-PropertyValue `
                        -Object $Endpoint.createdBy `
                        -Name "displayName"

                $CreatedByUniqueName =
                    Get-PropertyValue `
                        -Object $Endpoint.createdBy `
                        -Name "uniqueName"

                $CreatedById =
                    Get-PropertyValue `
                        -Object $Endpoint.createdBy `
                        -Name "id"
            }

            $AuthScheme = ""

            if ($null -ne $Endpoint.authorization) {
                $AuthScheme =
                    Get-PropertyValue `
                        -Object $Endpoint.authorization `
                        -Name "scheme"
            }

            $SubscriptionId = ""
            $SubscriptionName = ""
            $TenantId = ""
            $ServicePrincipalId = ""
            $AuthenticationType = ""

            if ($null -ne $Endpoint.data) {

                $SubscriptionId =
                    Get-PropertyValue `
                        -Object $Endpoint.data `
                        -Name "subscriptionId"

                $SubscriptionName =
                    Get-PropertyValue `
                        -Object $Endpoint.data `
                        -Name "subscriptionName"

                $TenantId =
                    Get-PropertyValue `
                        -Object $Endpoint.data `
                        -Name "tenantId"

                if ([string]::IsNullOrWhiteSpace($TenantId)) {
                    $TenantId =
                        Get-PropertyValue `
                            -Object $Endpoint.data `
                            -Name "tenantid"
                }

                $ServicePrincipalId =
                    Get-PropertyValue `
                        -Object $Endpoint.data `
                        -Name "serviceprincipalid"

                $AuthenticationType =
                    Get-PropertyValue `
                        -Object $Endpoint.data `
                        -Name "authenticationType"
            }

            # ----------------------------------------------------
            # Shared projects
            # ----------------------------------------------------

            $SharedProjects =
                New-Object System.Collections.Generic.List[string]

            if ($null -ne $Endpoint.serviceEndpointProjectReferences) {

                foreach ($Reference in @(
                    $Endpoint.serviceEndpointProjectReferences
                )) {

                    if ($null -ne $Reference.projectReference) {

                        $ReferenceProjectName =
                            Get-PropertyValue `
                                -Object $Reference.projectReference `
                                -Name "name"

                        if (-not [string]::IsNullOrWhiteSpace(
                            $ReferenceProjectName
                        )) {

                            if ($SharedProjects -notcontains
                                $ReferenceProjectName) {

                                $SharedProjects.Add(
                                    $ReferenceProjectName
                                )
                            }
                        }
                    }
                }
            }

            if ($SharedProjects.Count -eq 0) {
                $SharedProjects.Add([string]$Project.name)
            }

            # ----------------------------------------------------
            # Deduplicate shared service connections
            # ----------------------------------------------------

            if ($ByEndpointId.ContainsKey($EndpointId)) {

                $ExistingRecord =
                    $ByEndpointId[$EndpointId]

                $ExistingProjects = @(
                    $ExistingRecord.Projects -split "; " |
                    Where-Object {
                        -not [string]::IsNullOrWhiteSpace($_)
                    }
                )

                foreach ($SharedProject in $SharedProjects) {

                    if ($ExistingProjects -notcontains
                        [string]$SharedProject) {

                        $ExistingProjects +=
                            [string]$SharedProject
                    }
                }

                $ExistingRecord.Projects =
                    ($ExistingProjects -join "; ")

                continue
            }

            # ----------------------------------------------------
            # Credential preference
            # ----------------------------------------------------

            $PreferredGraphCredentialType = ""

            if ($AuthenticationType -match
                "spnKey|secret|Secret") {

                $PreferredGraphCredentialType = "Secret"
            }
            elseif ($AuthenticationType -match
                "spnCertificate|certificate|Certificate") {

                $PreferredGraphCredentialType = "Certificate"
            }

            # ----------------------------------------------------
            # Authentication category
            # ----------------------------------------------------

            $CredentialAuthType = "Unknown"

            switch -Regex ($AuthenticationType) {

                "spnKey|secret|Secret" {
                    $CredentialAuthType =
                        "Service Principal - Client Secret"
                    break
                }

                "spnCertificate|certificate|Certificate" {
                    $CredentialAuthType =
                        "Service Principal - Certificate"
                    break
                }

                "workloadIdentityFederation|WorkloadIdentityFederation|WIF" {
                    $CredentialAuthType =
                        "Workload Identity Federation"
                    break
                }

                "managedIdentity|ManagedIdentity" {
                    $CredentialAuthType =
                        "Managed Identity"
                    break
                }

                default {
                    if ($AuthScheme -eq "ServicePrincipal") {
                        $CredentialAuthType =
                            "Service Principal - Authentication type not exposed"
                    }
                }
            }

            # ----------------------------------------------------
            # Graph credential metadata
            # ----------------------------------------------------

            $CredentialType = "Not applicable"
            $CredentialDisplayName = ""
            $CredentialStartDate = ""
            $ExpirationDate = ""
            $CredentialStatus = "Not checked"
            $AllCredentialExpiries = ""
            $GraphDisplayName = ""
            $GraphAppId = ""
            $GraphLookupStatus = "Not applicable"

            $SkipGraphCredentialLookup =
                ($CredentialAuthType -eq
                    "Workload Identity Federation" -or
                 $CredentialAuthType -eq
                    "Managed Identity")

            if ($SkipGraphCredentialLookup) {

                $CredentialType =
                    $CredentialAuthType

                $CredentialStatus = "Not applicable"
                $GraphLookupStatus = "Not required"
            }
            elseif (-not [string]::IsNullOrWhiteSpace(
                $ServicePrincipalId
            )) {

                if (-not $GraphCache.ContainsKey(
                    $ServicePrincipalId
                )) {

                    try {

                        Write-Host `
                            "  Graph lookup: $ServicePrincipalId"

                        $GraphCache[$ServicePrincipalId] =
                            Invoke-GraphServicePrincipal `
                                -ServicePrincipalId $ServicePrincipalId `
                                -TenantId $TenantId
                    }
                    catch {

                        $GraphCache[$ServicePrincipalId] =
                            [PSCustomObject]@{
                                GraphLookupFailed = $true
                                Error =
                                    $_.Exception.Message
                            }
                    }
                }

                $GraphSP =
                    $GraphCache[$ServicePrincipalId]

                if ($GraphSP.PSObject.Properties[
                    "GraphLookupFailed"
                ]) {

                    $CredentialType =
                        "Lookup failed"

                    $CredentialStatus =
                        "Graph lookup failed"

                    $GraphLookupStatus =
                        [string]$GraphSP.Error
                }
                else {

                    $GraphInfo =
                        Get-GraphCredentialInfo `
                            -ServicePrincipal $GraphSP `
                            -PreferredType `
                                $PreferredGraphCredentialType

                    $CredentialType =
                        [string]$GraphInfo.CredentialType

                    $CredentialDisplayName =
                        [string]$GraphInfo.CredentialDisplayName

                    $CredentialStartDate =
                        [string]$GraphInfo.CredentialStartDate

                    $ExpirationDate =
                        [string]$GraphInfo.ExpirationDate

                    $CredentialStatus =
                        [string]$GraphInfo.CredentialStatus

                    $AllCredentialExpiries =
                        [string]$GraphInfo.AllCredentialExpiries

                    $GraphDisplayName =
                        [string]$GraphInfo.GraphDisplayName

                    $GraphAppId =
                        [string]$GraphInfo.GraphAppId

                    $GraphLookupStatus = "Success"
                }
            }
            else {

                $CredentialType =
                    "No Service Principal ID"

                $CredentialStatus =
                    "Not applicable"

                $GraphLookupStatus =
                    "No Service Principal ID"
            }

            # ----------------------------------------------------
            # Audit creation date / creator
            # ----------------------------------------------------

            $CreationEvent = $null

            if ($AuditEntries.Count -gt 0) {

                $CreationEvent =
                    Find-ServiceConnectionCreationEvent `
                        -AuditEntries $AuditEntries `
                        -EndpointId $EndpointId `
                        -EndpointName $EndpointName `
                        -ProjectId ([string]$Project.id)
            }

            $CreatedDate = ""
            $CreatedDateSource = "Not available"

            if ($null -ne $CreationEvent) {

                $CreatedDate =
                    [string]$CreationEvent.timestamp

                $CreatedDateSource =
                    "Azure DevOps Audit Log"

                # Audit actor is the strongest available historical
                # creator signal. Fall back to endpoint.createdBy
                # if a particular actor field is missing.
                if (-not [string]::IsNullOrWhiteSpace(
                    [string]$CreationEvent.actorDisplayName
                )) {

                    $CreatedByName =
                        [string]$CreationEvent.actorDisplayName
                }

                if (-not [string]::IsNullOrWhiteSpace(
                    [string]$CreationEvent.actorUPN
                )) {

                    $CreatedByUniqueName =
                        [string]$CreationEvent.actorUPN
                }

                if (-not [string]::IsNullOrWhiteSpace(
                    [string]$CreationEvent.actorUserId
                )) {

                    $CreatedById =
                        [string]$CreationEvent.actorUserId
                }
            }
            elseif ($AuditEntries.Count -gt 0) {

                $CreatedDateSource =
                    "Not found in available audit retention"
            }
            else {

                $CreatedDateSource =
                    "Audit log unavailable"
            }

            # ----------------------------------------------------
            # Current owner
            # ----------------------------------------------------

            $AdoOwner =
                Get-PropertyValue `
                    -Object $Endpoint `
                    -Name "owner"

            $CurrentOwner =
                "Not exposed as a human owner by Service Connection API"

            # ----------------------------------------------------
            # Renewal guidance
            # ----------------------------------------------------

            $RenewalProcess =
                "Manual review - organization renewal process is not exposed by Azure DevOps API"

            if ($CredentialAuthType -eq
                "Workload Identity Federation") {

                $RenewalProcess =
                    "No client secret/certificate expiration; verify federation configuration and organizational rotation process"
            }
            elseif ($CredentialAuthType -eq
                "Managed Identity") {

                $RenewalProcess =
                    "No client secret/certificate expiration; review managed identity lifecycle"
            }
            elseif ($CredentialStatus -eq "Expired") {

                $RenewalProcess =
                    "Credential expired - renew/replace underlying Entra credential according to organization process"
            }
            elseif ($CredentialStatus -eq
                "Expires within 30 days" -or
                    $CredentialStatus -eq
                "Expires within 90 days") {

                $RenewalProcess =
                    "Renew/replace underlying Entra credential before ExpirationDate according to organization process"
            }

            # ----------------------------------------------------
            # Review status
            # ----------------------------------------------------

            $ReviewStatus = "Ready for Review"

            if ($CredentialStatus -eq "Expired" -or
                $CredentialStatus -eq
                    "Expires within 30 days") {

                $ReviewStatus = "Action Required"
            }
            elseif ($CredentialStatus -eq
                "Expires within 90 days") {

                $ReviewStatus = "Review Soon"
            }
            elseif ($CreatedDateSource -ne
                "Azure DevOps Audit Log") {

                $ReviewStatus = "Needs Review"
            }

            # ----------------------------------------------------
            # Inventory record
            # ----------------------------------------------------

            $Record =
                [PSCustomObject][ordered]@{

                    Organization =
                        $Organization

                    Project =
                        [string]$Project.name

                    ProjectId =
                        [string]$Project.id

                    Projects =
                        ($SharedProjects -join "; ")

                    ServiceConnectionName =
                        $EndpointName

                    ServiceConnectionId =
                        $EndpointId

                    ServiceConnectionType =
                        $EndpointType

                    AuthenticationScheme =
                        $AuthScheme

                    AuthenticationType =
                        $AuthenticationType

                    CredentialAuthType =
                        $CredentialAuthType

                    CreatedDate =
                        $CreatedDate

                    CreatedDateSource =
                        $CreatedDateSource

                    CreatedBy =
                        $CreatedByName

                    CreatedByEmailOrUPN =
                        $CreatedByUniqueName

                    CreatedById =
                        $CreatedById

                    CurrentOwner =
                        $CurrentOwner

                    ADOEndpointOwner =
                        $AdoOwner

                    ServicePrincipalId =
                        $ServicePrincipalId

                    ServicePrincipalDisplayName =
                        $GraphDisplayName

                    ApplicationClientId =
                        $GraphAppId

                    CredentialType =
                        $CredentialType

                    CredentialDisplayName =
                        $CredentialDisplayName

                    CredentialStartDate =
                        $CredentialStartDate

                    ExpirationDate =
                        $ExpirationDate

                    CredentialStatus =
                        $CredentialStatus

                    AllCredentialExpiries =
                        $AllCredentialExpiries

                    AzureSubscriptionName =
                        $SubscriptionName

                    AzureSubscriptionId =
                        $SubscriptionId

                    AzureTenantId =
                        $TenantId

                    IsShared =
                        Get-PropertyValue `
                            -Object $Endpoint `
                            -Name "isShared"

                    IsReady =
                        Get-PropertyValue `
                            -Object $Endpoint `
                            -Name "isReady"

                    Description =
                        Get-PropertyValue `
                            -Object $Endpoint `
                            -Name "description"

                    ConnectionUrl =
                        Get-PropertyValue `
                            -Object $Endpoint `
                            -Name "url"

                    RenewalProcess =
                        $RenewalProcess

                    Consumer =
                        "Manual review required"

                    PendingDeletion =
                        "NO"

                    ReviewStatus =
                        $ReviewStatus

                    GraphLookupStatus =
                        $GraphLookupStatus

                    Notes =
                        "CreatedBy identifies the creator, not necessarily the current owner. Expiration is based on Microsoft Graph credential metadata. Azure DevOps audit history is limited by retention."
                }

            $Inventory.Add($Record)
            $ByEndpointId[$EndpointId] = $Record
        }
    }
    catch {

        $Errors.Add(
            [PSCustomObject][ordered]@{
                ProjectId =
                    [string]$Project.id

                ProjectName =
                    [string]$Project.name

                Error =
                    $_.Exception.Message
            }
        )

        Write-Warning `
            "Could not read service connections from '$($Project.name)': $($_.Exception.Message)"
    }
}

Write-Progress `
    -Activity "Scanning Azure DevOps projects" `
    -Completed

# ------------------------------------------------------------
# Export
# ------------------------------------------------------------

$Inventory |
    Sort-Object Project, ServiceConnectionName |
    Export-Csv `
        -Path $OutputFile `
        -NoTypeInformation `
        -Encoding UTF8

if ($Errors.Count -gt 0) {

    $Errors |
        Export-Csv `
            -Path $ErrorFile `
            -NoTypeInformation `
            -Encoding UTF8
}

# ------------------------------------------------------------
# Summary
# ------------------------------------------------------------

Write-Host ""
Write-Host "============================================================"
Write-Host "Inventory completed"
Write-Host "============================================================"
Write-Host ""
Write-Host "Organization          : $Organization"
Write-Host "Projects scanned      : $($Projects.Count)"
Write-Host "Azure service conns   : $($Inventory.Count)"
Write-Host "Project errors        : $($Errors.Count)"
Write-Host ""
Write-Host "Inventory CSV:"
Write-Host (Resolve-Path $OutputFile)

if ($Errors.Count -gt 0) {

    Write-Host ""
    Write-Host "Errors CSV:"
    Write-Host (Resolve-Path $ErrorFile)
}

Write-Host ""
Write-Host "No service-connection secrets, tokens, passwords, or private keys were exported."
Write-Host ""
