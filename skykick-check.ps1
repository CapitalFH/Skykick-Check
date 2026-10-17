# SkyKick / ConnectWise Cloud Backup - read-only tenant check
[CmdletBinding()]
param(
    [guid]$TenantId,
    [datetimeoffset]$SinceUtc = [datetimeoffset]'2026-10-13T00:00:00Z',
    [datetimeoffset]$UntilUtc = [datetimeoffset]::UtcNow,
    [string]$OutputDirectory = (Join-Path (Get-Location) ('skykick-check-' + [datetime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8)))
)

$ErrorActionPreference = 'Stop'
function Invoke-SkykickRead {
    param([string]$Name, [string]$Query, [scriptblock]$Read)
    $started = [datetimeoffset]::UtcNow.ToString('o')
    try {
        $data = @(& $Read)
        [pscustomobject]@{ Name=$Name; Query=$Query; Status='Completed'; StartedAtUtc=$started; FinishedAtUtc=[datetimeoffset]::UtcNow.ToString('o'); Data=$data; Error=$null }
    } catch {
        Write-Warning "$Name failed; dependent checks are unavailable: $($_.Exception.Message)"
        [pscustomobject]@{ Name=$Name; Query=$Query; Status='Failed'; StartedAtUtc=$started; FinishedAtUtc=[datetimeoffset]::UtcNow.ToString('o'); Data=@(); Error=$_.Exception.Message }
    }
}

function Get-SkykickProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return }
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains($Name)) { return $Object[$Name] }
    $property = $Object.PSObject.Properties[$Name]
    if ($property -and $null -ne $property.Value) { return $property.Value }
    if ($Object.AdditionalProperties) { return $Object.AdditionalProperties[$Name] }
}

function ConvertTo-SkykickAppMetadata {
    param($Object, [string]$Kind)
    # Do not persist password hints, secretText or certificate bytes.
    [pscustomobject]@{
        Kind=$Kind; Id=$Object.Id; AppId=$Object.AppId; DisplayName=$Object.DisplayName
        AccountEnabled=$Object.AccountEnabled; AppOwnerOrganizationId=$Object.AppOwnerOrganizationId
        ServicePrincipalType=$Object.ServicePrincipalType
        PasswordCredentials=@($Object.PasswordCredentials | Where-Object { $null -ne $_ } | Select-Object KeyId,DisplayName,StartDateTime,EndDateTime)
        KeyCredentials=@($Object.KeyCredentials | Where-Object { $null -ne $_ } | Select-Object KeyId,DisplayName,StartDateTime,EndDateTime,Type,Usage)
    }
}

function Get-SkykickCredentialRows {
    param([object[]]$Objects, [datetimeoffset]$Since, [datetimeoffset]$Until)
    foreach ($obj in $Objects) {
        foreach ($collection in 'PasswordCredentials', 'KeyCredentials') {
            foreach ($credential in $obj.$collection) {
                if ($credential.StartDateTime -and [datetimeoffset]$credential.StartDateTime -ge $Since -and [datetimeoffset]$credential.StartDateTime -le $Until) {
                    [pscustomobject]@{
                        Object=$obj.DisplayName; ObjectId=$obj.Id; Kind=$obj.Kind; AppId=$obj.AppId
                        CredentialType=$collection; Name=$credential.DisplayName; KeyId=$credential.KeyId
                        ValidFromUtc=([datetimeoffset]$credential.StartDateTime).ToUniversalTime().ToString('o')
                        ValidUntilUtc=if ($credential.EndDateTime) { ([datetimeoffset]$credential.EndDateTime).ToUniversalTime().ToString('o') } else { $null }
                    }
                }
            }
        }
    }
}

function Get-SkykickAuditRows {
    param([object[]]$Events)
    foreach ($event in $Events) {
        $app = $event.InitiatedBy.App; $user = $event.InitiatedBy.User
        [pscustomobject]@{
            TimeUtc=([datetimeoffset]$event.ActivityDateTime).ToUniversalTime().ToString('o')
            EventId=$event.Id; Action=$event.ActivityDisplayName; Result=$event.Result
            AppName=$app.DisplayName; AppId=$app.AppId; ServicePrincipalId=$app.ServicePrincipalId
            User=$user.UserPrincipalName; UserId=$user.Id
            Target=(@($event.TargetResources | ForEach-Object { if ($_.DisplayName) { $_.DisplayName } else { $_.Id } }) -join ', ')
        }
    }
}

function New-SkykickSection {
    param([string]$Number, [string]$Title, [object[]]$Dependencies, [object[]]$Data)
    $failed = @($Dependencies | Where-Object { $_.Status -ne 'Completed' })
    Write-Host "`n$Number. $Title" -ForegroundColor Cyan
    if ($failed.Count) {
        Write-Host ('UNAVAILABLE: ' + ($failed.Name -join ', ') + '. No negative conclusion is possible.') -ForegroundColor Yellow
        return [pscustomobject]@{ Number=$Number; Title=$Title; Status='Unavailable'; Count=$null; Rows=@(); FailedSources=@($failed.Name) }
    }
    $items = @($Data)
    if (-not $items.Count) { Write-Host 'No matching records in the returned data (see coverage limits).' }
    else { $items | Format-Table -AutoSize -Wrap | Out-String -Width 250 | Write-Host }
    [pscustomobject]@{ Number=$Number; Title=$Title; Status='Completed'; Count=$items.Count; Rows=$items; FailedSources=@() }
}

function Write-SkykickEvidenceFile {
    param([string]$Path, [string]$Content)
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Content)
    # CreateNew also protects against a competing run after the directory check.
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
}
$since = $SinceUtc.ToUniversalTime()
$until = $UntilUtc.ToUniversalTime()
if ($since -ge $until) { throw 'SinceUtc must be earlier than UntilUtc.' }
if ($until -gt [datetimeoffset]::UtcNow) { throw 'UntilUtc must not be in the future.' }
if ($PSBoundParameters.ContainsKey('TenantId') -and $TenantId -eq [guid]::Empty) { throw 'TenantId must not be the empty GUID.' }
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $outputPath) { throw 'OutputDirectory already exists. Choose a new directory to preserve earlier evidence.' }

$modules = 'Microsoft.Graph.Authentication', 'Microsoft.Graph.Applications',
           'Microsoft.Graph.Identity.Governance', 'Microsoft.Graph.Users', 'Microsoft.Graph.Reports'
$missing = @($modules | Where-Object { -not (Get-Module -ListAvailable -Name $_) })
if ($missing.Count) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module $missing -Scope CurrentUser -Force -ErrorAction Stop
}
$connection = @{
    NoWelcome = $true; ContextScope = 'Process'; ErrorAction = 'Stop'
    Scopes = @('Directory.Read.All', 'AuditLog.Read.All', 'RoleManagement.Read.Directory', 'Application.Read.All')
}
if ($PSBoundParameters.ContainsKey('TenantId')) { $connection.TenantId = $TenantId.ToString() }
Connect-MgGraph @connection
$context = Get-MgContext -ErrorAction Stop
if (-not $context.TenantId) { throw 'Graph did not return an authenticated tenant.' }
if ($connection.TenantId -and $context.TenantId -ne $connection.TenantId) { throw 'Authenticated tenant does not match TenantId. No collection performed.' }

if (Test-Path -LiteralPath $outputPath) { throw 'OutputDirectory was created while authenticating. Choose a new directory.' }
$null = [IO.Directory]::CreateDirectory($outputPath)
$started = [datetimeoffset]::UtcNow.ToString('o')
$filter = "activityDateTime ge $($since.ToString('o')) and activityDateTime le $($until.ToString('o'))"
Write-Host "Tenant: $($context.TenantId); account: $($context.Account)"
Write-Host "Audit window (inclusive UTC): $($since.ToString('o')) to $($until.ToString('o'))"
Write-Host 'Collecting data, please wait...' -ForegroundColor Yellow

# -All follows SDK pagination. Any failed page invalidates the collection;
# partially emitted results must not be reported as an empty/complete check.
$spRead = Invoke-SkykickRead 'ServicePrincipals' 'GET /servicePrincipals; all pages; selected metadata' {
    Get-MgServicePrincipal -All -Property Id,AppId,DisplayName,AccountEnabled,AppOwnerOrganizationId,ServicePrincipalType,PasswordCredentials,KeyCredentials -ErrorAction Stop |
        ForEach-Object { ConvertTo-SkykickAppMetadata $_ 'Enterprise app' }
}
$appRead = Invoke-SkykickRead 'Applications' 'GET /applications; all pages; selected metadata' {
    Get-MgApplication -All -Property Id,AppId,DisplayName,PasswordCredentials,KeyCredentials -ErrorAction Stop |
        ForEach-Object { ConvertTo-SkykickAppMetadata $_ 'App registration' }
}
$roleRead = Invoke-SkykickRead 'RoleDefinitions' 'GET /roleManagement/directory/roleDefinitions; all pages' {
    Get-MgRoleManagementDirectoryRoleDefinition -All -ErrorAction Stop | Select-Object Id,DisplayName
}
$assignmentRead = Invoke-SkykickRead 'RoleAssignments' 'GET /roleManagement/directory/roleAssignments?$expand=principal; all pages' {
    Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal -ErrorAction Stop |
        Select-Object Id,PrincipalId,RoleDefinitionId,DirectoryScopeId,AppScopeId,Principal
}
$userRead = Invoke-SkykickRead 'Users' 'GET /users; all pages; selected metadata' {
    Get-MgUser -All -Property Id,DisplayName,UserPrincipalName,CreatedDateTime,AccountEnabled -ErrorAction Stop |
        Select-Object Id,DisplayName,UserPrincipalName,CreatedDateTime,AccountEnabled
}
$auditRead = Invoke-SkykickRead 'DirectoryAudits' "GET /auditLogs/directoryAudits; all pages; filter=$filter" {
    Get-MgAuditLogDirectoryAudit -All -Filter $filter -ErrorAction Stop |
        Select-Object Id,ActivityDateTime,ActivityDisplayName,Category,Result,ResultReason,InitiatedBy,TargetResources,CorrelationId
}
$reads = @($spRead, $appRead, $roleRead, $assignmentRead, $userRead, $auditRead)
$allSPs = @($spRead.Data); $allApps = @($appRead.Data); $assignments = @($assignmentRead.Data)
$roleNames = @{}
foreach ($role in $roleRead.Data) { $roleNames[$role.Id] = $role.DisplayName }

$skykickTid = '3f9cd7a0-127a-4ed4-bf06-2f830d5616b7'
$r1 = @($allSPs | Where-Object {
    $_.DisplayName -match 'SkyKick|ConnectWise' -or $_.AppOwnerOrganizationId -eq $skykickTid
} | Select-Object DisplayName,Id,AppId,AppOwnerOrganizationId,AccountEnabled,@{n='Review';e={
    if ($_.AccountEnabled -eq $true) { 'Enabled: verify product/owner and incident relevance' }
    elseif ($_.AccountEnabled -eq $false) { 'Disabled at collection' }
    else { 'Unknown: accountEnabled was not returned' }
}})
$r2 = @($assignments | Where-Object {
    (Get-SkykickProperty $_.Principal '@odata.type') -eq '#microsoft.graph.servicePrincipal'
} | ForEach-Object {
    [pscustomobject]@{
        Role=$roleNames[$_.RoleDefinitionId]; RoleId=$_.RoleDefinitionId
        App=Get-SkykickProperty $_.Principal 'displayName'; AppId=Get-SkykickProperty $_.Principal 'appId'
        PrincipalId=$_.PrincipalId; Scope=$_.DirectoryScopeId
    }
})
$gaId = '62e90394-69f5-4237-9190-012177145e10'
$r3 = @($assignments | Where-Object { $_.RoleDefinitionId -eq $gaId } | ForEach-Object {
    [pscustomobject]@{
        Type=(Get-SkykickProperty $_.Principal '@odata.type') -replace '#microsoft.graph.', ''
        Name=Get-SkykickProperty $_.Principal 'displayName'; UPN=Get-SkykickProperty $_.Principal 'userPrincipalName'
        AppId=Get-SkykickProperty $_.Principal 'appId'; PrincipalId=$_.PrincipalId; Scope=$_.DirectoryScopeId
    }
})
# Credential StartDateTime is validity, NOT creation time. Directory audit below
# includes all actors and can retain changes to removed/backdated credentials.
$r4 = @(Get-SkykickCredentialRows ($allApps + $allSPs) $since $until)
$r5 = @($userRead.Data | Where-Object {
    $_.CreatedDateTime -and [datetimeoffset]$_.CreatedDateTime -ge $since -and [datetimeoffset]$_.CreatedDateTime -le $until
} | Select-Object Id,DisplayName,UserPrincipalName,@{n='CreatedUtc';e={([datetimeoffset]$_.CreatedDateTime).ToUniversalTime().ToString('o')}},AccountEnabled)
$r6 = @(Get-SkykickAuditRows $auditRead.Data)
$sections = @(
    New-SkykickSection '1' 'SkyKick / ConnectWise name or owner matches (review identity before action)' @($spRead) $r1
    New-SkykickSection '2' 'Apps with a direct directory role (review)' @($assignmentRead, $roleRead) $r2
    New-SkykickSection '3' 'Direct Global Administrator assignments (group members/PIM eligibility not expanded)' @($assignmentRead) $r3
    New-SkykickSection '4' 'Current credentials with validity starting in the window (not creation dates)' @($appRead, $spRead) $r4
    New-SkykickSection '5' 'Current users created in the window' @($userRead) $r5
    New-SkykickSection '6' 'Directory audit changes in the window (all actors)' @($auditRead) $r6
)
Write-Host "`nSUMMARY" -ForegroundColor Cyan
$sections | Select-Object Number,Title,Status,Count | Format-Table -AutoSize -Wrap | Out-String -Width 200 | Write-Host
$report = [ordered]@{
    SchemaVersion=1; TenantId=$context.TenantId; Account=$context.Account
    SinceUtc=$since.ToString('o'); UntilUtc=$until.ToString('o')
    StartedAtUtc=$started; FinishedAtUtc=[datetimeoffset]::UtcNow.ToString('o')
    Complete=@($reads | Where-Object { $_.Status -ne 'Completed' }).Count -eq 0
    ScriptSha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
    Collections=$reads; Sections=$sections
    Limitations=@(
        'Completed means SDK reads finished, not exhaustive retention/ingestion coverage or tenant clearance.'
        'Selected SDK objects are saved, not original HTTP bytes. Failed collections discard partial data and remain unavailable.'
        'Credential validity dates are not creation dates; removed credentials/users require audit history.'
        'Vendor-home-tenant credentials, federated credentials, PIM eligibility and role-assigned group members are not collected.'
        'Sign-ins, Graph request activity, mailbox/file access and provider-side backup downloads are not checked.'
        'Names or enabled state alone do not establish maliciousness or justify disabling unrelated products.'
    )
}
$reportPath = Join-Path $outputPath 'report.json'
$json = ConvertTo-Json -InputObject $report -Depth 40 -WarningAction Stop
Write-SkykickEvidenceFile $reportPath $json
$hash = (Get-FileHash -LiteralPath $reportPath -Algorithm SHA256).Hash
Write-SkykickEvidenceFile (Join-Path $outputPath 'report.sha256') "$hash  report.json`n"
Write-Host "Saved $reportPath (SHA256 $hash). Contains tenant information; keep it private."
Write-Host 'No recorded findings is not proof of no compromise or exfiltration. Review the coverage limits in the report.'
if (-not $report.Complete) { throw "One or more collections failed. Results are incomplete; see $reportPath." }
