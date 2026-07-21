[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$TenantId,
    [Parameter(Mandatory)] [string]$McpAppId,
    [string]$McpScope = "Mcp.Access",
    [string]$CliDisplayName = "Hunter Defender Agent CLI",
    [string]$BlueprintDisplayName = "Hunter Defender Identity Agent Blueprint",
    [string]$AgentDisplayName = "Hunter Defender Identity Agent - Local",
    [string]$RedirectUri = "http://localhost",
    [string]$EnvPath = (Join-Path $PSScriptRoot "../.env"),
    [switch]$RotateBlueprintSecret
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$GraphBeta = "https://graph.microsoft.com/beta"
$ODataTypeBlueprint = "#microsoft.graph.agentIdentityBlueprint"
$ODataTypeBlueprintPrincipal = "#microsoft.graph.agentIdentityBlueprintPrincipal"
$ODataTypeAgentIdentity = "#microsoft.graph.agentIdentity"
$AgentUserScope = "access_as_user"
$AgentUserScopeId = "4d4a6bc3-56d1-4ddb-8ed7-71d0663344cf"

function Invoke-GraphJson {
    param(
        [Parameter(Mandatory)] [ValidateSet("GET", "POST", "PATCH")] [string]$Method,
        [Parameter(Mandatory)] [string]$Uri,
        [hashtable]$Body
    )

    $parameters = @{
        Method = $Method
        Uri = $Uri
        Headers = @{ "OData-Version" = "4.0" }
        OutputType = "PSObject"
    }
    if ($null -ne $Body) {
        $parameters.Body = ($Body | ConvertTo-Json -Depth 20 -Compress)
        $parameters.ContentType = "application/json"
    }

    return Invoke-MgGraphRequest @parameters
}

function Get-GraphCollection {
    param([Parameter(Mandatory)] [string]$Uri)

    $items = @()
    $next = $Uri
    while ($next) {
        $response = Invoke-GraphJson -Method GET -Uri $next
        $items += @($response.value)
        $next = if ($response.PSObject.Properties.Name -contains '@odata.nextLink') {
            $response.'@odata.nextLink'
        } else {
            $null
        }
    }
    return $items
}

function Get-ApplicationByDisplayName {
    param([Parameter(Mandatory)] [string]$DisplayName)

    $escaped = $DisplayName.Replace("'", "''")
    $uri = "$GraphBeta/applications?`$filter=displayName eq '$escaped'&`$select=id,appId,displayName,identifierUris,publicClient,requiredResourceAccess"
    $matches = @(Get-GraphCollection -Uri $uri)
    if ($matches.Count -gt 1) {
        throw "More than one application named '$DisplayName' exists. Resolve duplicates before continuing."
    }
    return $matches | Select-Object -First 1
}

function Get-ServicePrincipalsByAppId {
    param([Parameter(Mandatory)] [string]$AppId)

    $uri = "$GraphBeta/servicePrincipals?`$filter=appId eq '$AppId'&`$select=id,appId,displayName,servicePrincipalType"
    return @(Get-GraphCollection -Uri $uri)
}

function Set-EnvValue {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [AllowEmptyString()] [string]$Value
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    if (Test-Path $Path) {
        foreach ($line in Get-Content $Path) {
            $lines.Add($line)
        }
    }
    $prefix = "$Name="
    $index = -1
    for ($position = 0; $position -lt $lines.Count; $position++) {
        if ($lines[$position].StartsWith($prefix, [StringComparison]::Ordinal)) {
            $index = $position
            break
        }
    }
    $entry = "$Name=$Value"
    if ($index -ge 0) {
        $lines[$index] = $entry
    } else {
        $lines.Add($entry)
    }
    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    [System.IO.File]::WriteAllLines($Path, $lines, [System.Text.UTF8Encoding]::new($false))
}

Write-Host "Connecting to Microsoft Graph tenant $TenantId..."
$scopes = @(
    "Application.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "AgentIdentityBlueprint.Create",
    "AgentIdentityBlueprint.ReadWrite.All",
    "AgentIdentityBlueprintPrincipal.Create",
    "AgentIdentity.Create.All",
    "AgentIdentity.ReadWrite.All",
    "User.Read"
)
Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
Connect-MgGraph -TenantId $TenantId -Scopes $scopes -ContextScope Process -NoWelcome

$organization = Invoke-GraphJson -Method GET -Uri "$GraphBeta/organization?`$select=id,displayName"
$connectedTenantId = [string]@($organization.value)[0].id
if ($connectedTenantId -ne $TenantId) {
    throw "Connected tenant '$connectedTenantId' does not match requested tenant '$TenantId'."
}

$currentUser = Invoke-GraphJson -Method GET -Uri "$GraphBeta/me?`$select=id,userPrincipalName,displayName"
$sponsorBinding = "$GraphBeta/users/$($currentUser.id)"
Write-Host "Sponsor: $($currentUser.userPrincipalName)"

$mcpApp = Invoke-GraphJson -Method GET -Uri "$GraphBeta/applications(appId='$McpAppId')?`$select=id,appId,displayName,api"
$mcpScopeDefinition = @($mcpApp.api.oauth2PermissionScopes | Where-Object { $_.value -eq $McpScope -and $_.isEnabled })
if ($mcpScopeDefinition.Count -ne 1) {
    throw "Enabled scope '$McpScope' was not found exactly once on MCP app '$McpAppId'."
}
$mcpScopeId = [string]$mcpScopeDefinition[0].id
$mcpPrincipals = @(Get-ServicePrincipalsByAppId -AppId $McpAppId)
if ($mcpPrincipals.Count -ne 1) {
    throw "Expected one MCP service principal for '$McpAppId', found $($mcpPrincipals.Count)."
}
$mcpPrincipal = $mcpPrincipals[0]
Write-Host "Reusing MCP resource app: $($mcpApp.displayName) ($McpAppId)"

$cliApp = Get-ApplicationByDisplayName -DisplayName $CliDisplayName
$requiredResourceAccess = @(
    @{
        resourceAppId = $McpAppId
        resourceAccess = @(@{ id = $mcpScopeId; type = "Scope" })
    }
)
$knownBlueprint = Get-ApplicationByDisplayName -DisplayName $BlueprintDisplayName
if ($null -ne $knownBlueprint) {
    $requiredResourceAccess += @{
        resourceAppId = [string]$knownBlueprint.appId
        resourceAccess = @(@{ id = $AgentUserScopeId; type = "Scope" })
    }
}
if ($null -eq $cliApp) {
    $cliApp = Invoke-GraphJson -Method POST -Uri "$GraphBeta/applications" -Body @{
        displayName = $CliDisplayName
        signInAudience = "AzureADMyOrg"
        isFallbackPublicClient = $true
        publicClient = @{ redirectUris = @($RedirectUri) }
        requiredResourceAccess = $requiredResourceAccess
    }
    Write-Host "Created public CLI app: $($cliApp.appId)"
} else {
    Invoke-GraphJson -Method PATCH -Uri "$GraphBeta/applications/$($cliApp.id)" -Body @{
        isFallbackPublicClient = $true
        publicClient = @{ redirectUris = @($RedirectUri) }
        requiredResourceAccess = $requiredResourceAccess
    } | Out-Null
    Write-Host "Reused public CLI app: $($cliApp.appId)"
}

$cliPrincipals = @(Get-ServicePrincipalsByAppId -AppId $cliApp.appId)
if ($cliPrincipals.Count -eq 0) {
    $cliPrincipal = Invoke-GraphJson -Method POST -Uri "$GraphBeta/servicePrincipals" -Body @{ appId = $cliApp.appId }
    Write-Host "Created CLI service principal."
} elseif ($cliPrincipals.Count -eq 1) {
    $cliPrincipal = $cliPrincipals[0]
} else {
    throw "Expected at most one CLI service principal, found $($cliPrincipals.Count)."
}

$grantUri = "$GraphBeta/oauth2PermissionGrants?`$filter=clientId eq '$($cliPrincipal.id)' and resourceId eq '$($mcpPrincipal.id)' and consentType eq 'AllPrincipals'"
$grants = @(Get-GraphCollection -Uri $grantUri)
if ($grants.Count -eq 0) {
    $grantStart = [DateTimeOffset]::UtcNow.ToString("o")
    $grantExpiry = [DateTimeOffset]::UtcNow.AddYears(1).ToString("o")
    Invoke-GraphJson -Method POST -Uri "$GraphBeta/oauth2PermissionGrants" -Body @{
        clientId = $cliPrincipal.id
        consentType = "AllPrincipals"
        resourceId = $mcpPrincipal.id
        scope = $McpScope
        startTime = $grantStart
        expiryTime = $grantExpiry
    } | Out-Null
    Write-Host "Granted tenant-wide delegated consent for $McpScope."
} else {
    $grant = $grants[0]
    $grantScopes = @(([string]$grant.scope).Split(' ', [StringSplitOptions]::RemoveEmptyEntries))
    if ($McpScope -notin $grantScopes) {
        $newScope = (@($grantScopes + $McpScope) | Sort-Object -Unique) -join " "
        Invoke-GraphJson -Method PATCH -Uri "$GraphBeta/oauth2PermissionGrants/$($grant.id)" -Body @{ scope = $newScope } | Out-Null
    }
    Write-Host "Delegated consent already exists."
}

$blueprint = Get-ApplicationByDisplayName -DisplayName $BlueprintDisplayName
if ($null -eq $blueprint) {
    $blueprint = Invoke-GraphJson -Method POST -Uri "$GraphBeta/applications" -Body @{
        '@odata.type' = $ODataTypeBlueprint
        displayName = $BlueprintDisplayName
        'sponsors@odata.bind' = @($sponsorBinding)
    }
    Write-Host "Created Agent Identity Blueprint: $($blueprint.appId)"
} else {
    Write-Host "Reused Agent Identity Blueprint: $($blueprint.appId)"
}

Invoke-GraphJson -Method PATCH -Uri "$GraphBeta/applications/$($blueprint.id)" -Body @{
    identifierUris = @("api://$($blueprint.appId)")
    api = @{
        requestedAccessTokenVersion = 2
        oauth2PermissionScopes = @(
            @{
                id = $AgentUserScopeId
                value = $AgentUserScope
                type = "User"
                isEnabled = $true
                adminConsentDisplayName = "Access Hunter Defender Identity Agent"
                adminConsentDescription = "Allow the CLI to invoke the interactive Hunter Defender Identity Agent."
                userConsentDisplayName = "Access Hunter Defender Identity Agent"
                userConsentDescription = "Allow this CLI to invoke the interactive Hunter Defender Identity Agent."
            }
        )
    }
} | Out-Null

$blueprintPrincipals = @(Get-ServicePrincipalsByAppId -AppId $blueprint.appId)
if ($blueprintPrincipals.Count -eq 0) {
    $blueprintPrincipal = Invoke-GraphJson -Method POST -Uri "$GraphBeta/servicePrincipals" -Body @{
        '@odata.type' = $ODataTypeBlueprintPrincipal
        appId = $blueprint.appId
    }
    Write-Host "Created Blueprint Principal."
} elseif ($blueprintPrincipals.Count -gt 1) {
    throw "Expected one Blueprint Principal, found $($blueprintPrincipals.Count)."
} else {
    $blueprintPrincipal = $blueprintPrincipals[0]
    Write-Host "Blueprint Principal already exists."
}

$completeRequiredResourceAccess = @(
    @{
        resourceAppId = $McpAppId
        resourceAccess = @(@{ id = $mcpScopeId; type = "Scope" })
    },
    @{
        resourceAppId = [string]$blueprint.appId
        resourceAccess = @(@{ id = $AgentUserScopeId; type = "Scope" })
    }
)
Invoke-GraphJson -Method PATCH -Uri "$GraphBeta/applications/$($cliApp.id)" -Body @{
    requiredResourceAccess = $completeRequiredResourceAccess
} | Out-Null

$blueprintGrantUri = "$GraphBeta/oauth2PermissionGrants?`$filter=clientId eq '$($cliPrincipal.id)' and resourceId eq '$($blueprintPrincipal.id)' and consentType eq 'AllPrincipals'"
$blueprintGrants = @(Get-GraphCollection -Uri $blueprintGrantUri)
if ($blueprintGrants.Count -eq 0) {
    Invoke-GraphJson -Method POST -Uri "$GraphBeta/oauth2PermissionGrants" -Body @{
        clientId = $cliPrincipal.id
        consentType = "AllPrincipals"
        resourceId = $blueprintPrincipal.id
        scope = $AgentUserScope
        startTime = [DateTimeOffset]::UtcNow.ToString("o")
        expiryTime = [DateTimeOffset]::UtcNow.AddYears(1).ToString("o")
    } | Out-Null
    Write-Host "Granted tenant-wide delegated consent for $AgentUserScope."
} else {
    $blueprintGrant = $blueprintGrants[0]
    if ([string]$blueprintGrant.scope -ne $AgentUserScope) {
        Invoke-GraphJson -Method PATCH -Uri "$GraphBeta/oauth2PermissionGrants/$($blueprintGrant.id)" -Body @{
            scope = $AgentUserScope
        } | Out-Null
    }
    Write-Host "Blueprint delegated consent already exists."
}

$escapedAgentName = $AgentDisplayName.Replace("'", "''")
$agentUri = "$GraphBeta/servicePrincipals?`$filter=displayName eq '$escapedAgentName'&`$select=id,appId,displayName,servicePrincipalType"
$agentMatches = @(Get-GraphCollection -Uri $agentUri | Where-Object { $_.servicePrincipalType -eq "ServiceIdentity" })
if ($agentMatches.Count -gt 1) {
    throw "More than one Agent Identity named '$AgentDisplayName' exists."
}
if ($agentMatches.Count -eq 0) {
    $agentIdentity = Invoke-GraphJson -Method POST -Uri "$GraphBeta/servicePrincipals" -Body @{
        '@odata.type' = $ODataTypeAgentIdentity
        displayName = $AgentDisplayName
        agentIdentityBlueprintId = $blueprint.appId
        'sponsors@odata.bind' = @($sponsorBinding)
    }
    Write-Host "Created Agent Identity: $($agentIdentity.appId)"
} else {
    $agentIdentity = $agentMatches[0]
    Write-Host "Reused Agent Identity: $($agentIdentity.appId)"
}

$envExists = Test-Path $EnvPath
$existingSecret = if ($envExists) {
    $secretLine = Get-Content $EnvPath | Where-Object { $_.StartsWith("ENTRA_AGENT_BLUEPRINT_CLIENT_SECRET=", [StringComparison]::Ordinal) } | Select-Object -First 1
    if ($secretLine) { $secretLine.Substring($secretLine.IndexOf('=') + 1) } else { $null }
} else { $null }

$blueprintSecret = $existingSecret
if (-not $blueprintSecret -or $RotateBlueprintSecret) {
    $credentialName = "Hunter Defender local sidecar"
    $blueprintCredentials = Invoke-GraphJson -Method GET -Uri "$GraphBeta/applications/$($blueprint.id)?`$select=passwordCredentials"
    foreach ($passwordCredential in @($blueprintCredentials.passwordCredentials | Where-Object { $_.displayName -eq $credentialName })) {
        Invoke-GraphJson -Method POST -Uri "$GraphBeta/applications/$($blueprint.id)/removePassword" -Body @{
            keyId = $passwordCredential.keyId
        } | Out-Null
    }
    $expiresAt = [DateTimeOffset]::UtcNow.AddDays(90).ToString("o")
    $credential = Invoke-GraphJson -Method POST -Uri "$GraphBeta/applications/$($blueprint.id)/addPassword" -Body @{
        passwordCredential = @{
            displayName = $credentialName
            endDateTime = $expiresAt
        }
    }
    $blueprintSecret = [string]$credential.secretText
    if (-not $blueprintSecret) {
        throw "Graph did not return the Blueprint secret text."
    }
    Write-Host "Created a 90-day Blueprint development credential."
} else {
    Write-Host "Reused the Blueprint credential already stored in .env."
}

$mcpAudience = $McpAppId
$mcpScopeValue = "api://$McpAppId/$McpScope"
$settings = [ordered]@{
    AZURE_TENANT_ID = $TenantId
    ENTRA_CLI_CLIENT_ID = [string]$cliApp.appId
    ENTRA_AGENT_BLUEPRINT_CLIENT_ID = [string]$blueprint.appId
    ENTRA_AGENT_BLUEPRINT_CLIENT_SECRET = $blueprintSecret
    ENTRA_AGENT_IDENTITY_CLIENT_ID = [string]$agentIdentity.appId
    ENTRA_USER_SCOPE = "api://$($blueprint.appId)/$AgentUserScope"
    ENTRA_MCP_AUDIENCE = $mcpAudience
    ENTRA_MCP_ISSUER = "https://login.microsoftonline.com/$TenantId/v2.0"
    ENTRA_MCP_USER_SCOPE = $McpScope
    ENTRA_MCP_AGENT_ROLE = "Mcp.Invoke"
    ENTRA_MCP_SCOPE = $mcpScopeValue
    HUNTER_DEFENDER_MCP_URL = "http://127.0.0.1:8000/mcp"
    ENTRA_SIDECAR_URL = "http://127.0.0.1:5000"
    ENTRA_SIDECAR_SERVICE_NAME = "HunterDefenderMcp"
}
foreach ($entry in $settings.GetEnumerator()) {
    Set-EnvValue -Path $EnvPath -Name $entry.Key -Value ([string]$entry.Value)
}
if (-not $IsWindows) {
    [System.IO.File]::SetUnixFileMode(
        (Resolve-Path $EnvPath),
        [System.IO.UnixFileMode]::UserRead -bor [System.IO.UnixFileMode]::UserWrite
    )
}

Write-Host "Provisioning complete. Configuration was written to $EnvPath"
Write-Host "CLI app ID: $($cliApp.appId)"
Write-Host "Blueprint app ID: $($blueprint.appId)"
Write-Host "Agent Identity app ID: $($agentIdentity.appId)"
Write-Host "The Blueprint secret was stored only in .env and was not printed."
