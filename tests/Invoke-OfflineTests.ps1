# Synthetic end-to-end tests. No Graph modules, tenant access or Pester required.
$ErrorActionPreference = 'Stop'
$checker = Join-Path (Split-Path $PSScriptRoot -Parent) 'skykick-check.ps1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('skykick-offline-tests-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($testRoot)
$script:passed = 0

function Assert-True($Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Assert-Throws([scriptblock]$Action, [string]$Pattern) {
    try { & $Action } catch {
        Assert-True ($_.Exception.Message -like $Pattern) "Unexpected exception: $($_.Exception.Message)"
        return
    }
    throw "Expected exception: $Pattern"
}
function Test-Case([string]$Name, [scriptblock]$Action) {
    & $Action
    $script:passed++
    Write-Host "PASS $Name"
}
function Reset-Fixture {
    $global:SkykickTestFixture = @{
        TenantId='11111111-1111-1111-1111-111111111111'; Connects=0; Reads=0
        FailUsers=$false; FailSPs=$false; Empty=$false; UnknownEnabled=$false; CollideOutput=$false
    }
}

# These functions shadow every SDK/network/module-install command used by the
# script. Any unexpected module install fails instead of accessing the network.
function Get-Module { param($Name, [switch]$ListAvailable) [pscustomobject]@{Name=$Name} }
function Install-Module { throw 'Offline tests must never install modules.' }
function Connect-MgGraph {
    [CmdletBinding()] param($Scopes, $TenantId, $ContextScope, [switch]$NoWelcome)
    $global:SkykickTestFixture.Connects++
}
function Get-MgContext {
    [CmdletBinding()] param()
    [pscustomobject]@{TenantId=$global:SkykickTestFixture.TenantId;Account='analyst@example.invalid'}
}
function Get-MgServicePrincipal {
    [CmdletBinding()] param([switch]$All, $Property)
    $global:SkykickTestFixture.Reads++
    if ($global:SkykickTestFixture.Empty) { return }
    if ($global:SkykickTestFixture.CollideOutput) {
        [IO.File]::WriteAllText((Join-Path $global:SkykickTestFixture.OutputPath 'report.json'), 'SENTINEL_EVIDENCE')
    }
    [pscustomobject]@{
        Id='sp-example';AppId='22222222-2222-2222-2222-222222222222'
        DisplayName='ConnectWise Example Product';AccountEnabled=if ($global:SkykickTestFixture.UnknownEnabled) { $null } else { $true };AppOwnerOrganizationId='other-vendor'
        PasswordCredentials=@();KeyCredentials=@();ServicePrincipalType='Application'
    }
    if ($global:SkykickTestFixture.FailSPs) { Write-Error 'Synthetic page-two failure' }
}
function Get-MgApplication {
    [CmdletBinding()] param([switch]$All, $Property)
    $global:SkykickTestFixture.Reads++
    if ($global:SkykickTestFixture.Empty) { return }
    [pscustomobject]@{
        Id='app-example';AppId='33333333-3333-3333-3333-333333333333';DisplayName='Example app'
        PasswordCredentials=@([pscustomobject]@{
            KeyId='backdated';DisplayName='Example';StartDateTime='2024-01-01T00:00:00Z'
            EndDateTime='2025-01-01T00:00:00Z';SecretText='SYNTHETIC_NOT_FOR_EXPORT';Hint='SYN'
        })
        KeyCredentials=@([pscustomobject]@{
            KeyId='current-key';StartDateTime='2024-01-14T10:00:00+10:00';EndDateTime='2025-01-14T00:00:00Z'
            DisplayName='Example cert';Type='AsymmetricX509Cert';Usage='Verify';Key='SYNTHETIC_CERTIFICATE_BYTES'
        })
    }
}
function Get-MgRoleManagementDirectoryRoleDefinition {
    [CmdletBinding()] param([switch]$All)
    $global:SkykickTestFixture.Reads++
    if (-not $global:SkykickTestFixture.Empty) { [pscustomobject]@{Id='62e90394-69f5-4237-9190-012177145e10';DisplayName='Global Administrator'} }
}
function Get-MgRoleManagementDirectoryRoleAssignment {
    [CmdletBinding()] param([switch]$All, $ExpandProperty)
    $global:SkykickTestFixture.Reads++
    if ($global:SkykickTestFixture.Empty) { return }
    [pscustomobject]@{
        Id='assignment-example';PrincipalId='sp-example';RoleDefinitionId='62e90394-69f5-4237-9190-012177145e10';DirectoryScopeId='/'
        Principal=[pscustomobject]@{AdditionalProperties=@{'@odata.type'='#microsoft.graph.servicePrincipal';displayName='Example app';appId='22222222-2222-2222-2222-222222222222'}}
    }
}
function Get-MgUser {
    [CmdletBinding()] param([switch]$All, $Property)
    $global:SkykickTestFixture.Reads++
    if ($global:SkykickTestFixture.Empty) { return }
    [pscustomobject]@{Id='user-example';DisplayName='Example';UserPrincipalName='example@example.invalid';CreatedDateTime='2024-01-15T00:00:00Z';AccountEnabled=$true}
    if ($global:SkykickTestFixture.FailUsers) { Write-Error 'Synthetic 403 after a partial result' }
    [pscustomobject]@{Id='later-user';CreatedDateTime='2024-02-01T00:00:00Z'}
}
function Get-MgAuditLogDirectoryAudit {
    [CmdletBinding()] param([switch]$All, $Filter)
    $global:SkykickTestFixture.Reads++
    $global:SkykickTestFixture.AuditFilter=$Filter
    if ($global:SkykickTestFixture.Empty) { return }
    foreach ($kind in 'app-id-only', 'sp-id-only', 'user-credential-change') {
        $actor = switch ($kind) {
            'app-id-only' { @{App=@{AppId='22222222-2222-2222-2222-222222222222';DisplayName=$null}} }
            'sp-id-only' { @{App=@{ServicePrincipalId='sp-example';DisplayName=$null}} }
            'user-credential-change' { @{User=@{Id='user-example';UserPrincipalName='example@example.invalid'}} }
        }
        [pscustomobject]@{
            Id=$kind;ActivityDateTime='2024-01-15T01:02:03Z';ActivityDisplayName='Update application - Certificates and secrets management'
            Result='success';InitiatedBy=$actor;CorrelationId='correlation-example'
            TargetResources=@(@{Id='app-example';DisplayName=$null;ModifiedProperties=@(@{DisplayName='KeyDescription';NewValue='backdated'})})
        }
    }
}
function Invoke-Checker([string]$Name, [hashtable]$Arguments=@{}) {
    $path = Join-Path $testRoot $Name
    $global:SkykickTestFixture.OutputPath=$path
    & $checker -SinceUtc '2024-01-13T10:00:00+10:00' -UntilUtc '2024-01-17T10:00:00+10:00' -OutputDirectory $path @Arguments *> (Join-Path $testRoot ($Name + '.log'))
    Get-Content -LiteralPath (Join-Path $path 'report.json') -Raw | ConvertFrom-Json
}

Test-Case 'all actors retained; validity date not mislabeled; safe metadata and hash exported' {
    Reset-Fixture
    $r = Invoke-Checker 'success' @{TenantId=$global:SkykickTestFixture.TenantId}
    Assert-True $r.Complete 'Successful fixture should complete.'
    Assert-True ($r.Sections.Count -eq 6) 'Expected six sections.'
    Assert-True ($r.Sections[5].Rows.Count -eq 3) 'Missing app-ID-only, SP-ID-only or user audit event.'
    Assert-True ($r.Sections[5].Rows[2].UserId -eq 'user-example') 'User-initiated credential change omitted.'
    Assert-True ($r.Sections[5].Rows[0].Target -eq 'app-example') 'Missing target-ID fallback.'
    Assert-True ($r.Sections[3].Rows.Count -eq 1) 'Validity filter should not pretend to detect the backdated addition.'
    Assert-True ($r.Sections[3].Rows[0].ValidFromUtc -eq '2024-01-14T00:00:00.0000000+00:00') 'Credential time was not normalized to UTC.'
    Assert-True ($r.Sections[3].Rows[0].PSObject.Properties.Name -notcontains 'Created') 'Validity must not be labeled creation.'
    Assert-True ($r.Sections[4].Count -eq 1) 'User created after UntilUtc leaked into results.'
    Assert-True ($r.Sections[1].Rows[0].App -eq 'Example app') 'SDK AdditionalProperties not handled.'
    Assert-True ($r.Collections.Count -eq 6) 'Collection status missing.'
    $file = Join-Path $testRoot 'success/report.json'
    $text = Get-Content -LiteralPath $file -Raw
    Assert-True ($text -notmatch 'SYNTHETIC_NOT_FOR_EXPORT|SYNTHETIC_CERTIFICATE_BYTES|"Hint"|disable now') 'Sensitive metadata or blanket disable advice leaked.'
    $hash = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
    Assert-True ((Get-Content (Join-Path $testRoot 'success/report.sha256') -Raw).StartsWith($hash)) 'Saved hash mismatch.'
    Assert-True ($global:SkykickTestFixture.AuditFilter -eq 'activityDateTime ge 2024-01-13T00:00:00.0000000+00:00 and activityDateTime le 2024-01-17T00:00:00.0000000+00:00') 'UTC bounds not applied to Graph query.'
}
Test-Case 'a failed later page cannot become zero findings or partial success' {
    Reset-Fixture; $global:SkykickTestFixture.FailUsers=$true
    Assert-Throws { Invoke-Checker 'failed-users' } '*Results are incomplete*'
    $r = Get-Content (Join-Path $testRoot 'failed-users/report.json') -Raw | ConvertFrom-Json
    Assert-True (-not $r.Complete) 'Failure was reported as complete.'
    Assert-True ($r.Sections[4].Status -eq 'Unavailable' -and $null -eq $r.Sections[4].Count) 'Failure became a zero count.'
    Assert-True ($r.Sections[4].Rows.Count -eq 0) 'Partial rows represented as complete.'
    Assert-True ($r.Sections[5].Status -eq 'Completed') 'Independent audit read should be preserved.'
}
Test-Case 'shared failed input invalidates every dependent check' {
    Reset-Fixture; $global:SkykickTestFixture.FailSPs=$true
    Assert-Throws { Invoke-Checker 'failed-sp' } '*Results are incomplete*'
    $r = Get-Content (Join-Path $testRoot 'failed-sp/report.json') -Raw | ConvertFrom-Json
    Assert-True ($r.Sections[0].Status -eq 'Unavailable' -and $r.Sections[3].Status -eq 'Unavailable') 'Failed SP page did not invalidate both sections.'
}
Test-Case 'successful empty collections have zero rows without phantom null entries' {
    Reset-Fixture; $global:SkykickTestFixture.Empty=$true
    $r = Invoke-Checker 'empty'
    Assert-True $r.Complete 'Empty completed reads should not be failures.'
    Assert-True (@($r.Sections | Where-Object { $_.Count -ne 0 -or $_.Status -ne 'Completed' }).Count -eq 0) 'Empty read was misreported.'
}
Test-Case 'tenant mismatch fails before any tenant read' {
    Reset-Fixture
    Assert-Throws { Invoke-Checker 'wrong-tenant' @{TenantId='99999999-9999-9999-9999-999999999999'} } '*does not match*'
    Assert-True ($global:SkykickTestFixture.Reads -eq 0) 'Read from the wrong tenant.'
}
Test-Case 'existing evidence directory is never overwritten' {
    Reset-Fixture
    Assert-Throws { Invoke-Checker 'success' } '*already exists*'
    Assert-True ($global:SkykickTestFixture.Connects -eq 0) 'Authenticated before validating the output path.'
}
Test-Case 'invalid time range fails before authentication' {
    Reset-Fixture
    Assert-Throws { & $checker -SinceUtc '2024-02-01Z' -UntilUtc '2024-01-01Z' } '*SinceUtc must be earlier*'
    Assert-True ($global:SkykickTestFixture.Connects -eq 0) 'Authenticated with invalid date range.'
}
Test-Case 'unknown account state is never labeled disabled' {
    Reset-Fixture; $global:SkykickTestFixture.UnknownEnabled=$true
    $r = Invoke-Checker 'unknown-state'
    Assert-True ($r.Sections[0].Rows[0].Review -like 'Unknown:*') 'Missing accountEnabled became containment proof.'
}
Test-Case 'an evidence file created after preflight is never overwritten' {
    Reset-Fixture; $global:SkykickTestFixture.CollideOutput=$true
    Assert-Throws { Invoke-Checker 'racing-output' } '*already exists*'
    Assert-True ((Get-Content (Join-Path $testRoot 'racing-output/report.json') -Raw) -eq 'SENTINEL_EVIDENCE') 'Concurrent evidence was overwritten.'
}
Write-Host "$script:passed offline tests passed on PowerShell $($PSVersionTable.PSVersion). Artifacts: $testRoot"
