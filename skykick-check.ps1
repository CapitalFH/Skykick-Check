# SkyKick / ConnectWise Cloud Backup - tenant check
# Shows a clean table per section, or "No findings".

# --- Install modules only if missing ---
$modules = 'Microsoft.Graph.Authentication','Microsoft.Graph.Applications',
           'Microsoft.Graph.Identity.Governance','Microsoft.Graph.Users','Microsoft.Graph.Reports'
$missing = $modules | Where-Object { -not (Get-Module -ListAvailable -Name $_) }
if ($missing) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Install-Module $missing -Scope CurrentUser -Force
}

Connect-MgGraph -NoWelcome -Scopes "Directory.Read.All","AuditLog.Read.All","RoleManagement.Read.Directory","Application.Read.All"

$since      = [datetime]"2026-10-13"
$skykickTid = '3f9cd7a0-127a-4ed4-bf06-2f830d5616b7'
$summary    = [ordered]@{}

function Show-Section {
    param([string]$Nr, [string]$Title, $Data, [string]$Key)
    Write-Host ""
    Write-Host ("=" * 90) -ForegroundColor DarkGray
    Write-Host " $Nr. $Title" -ForegroundColor Cyan
    Write-Host ("=" * 90) -ForegroundColor DarkGray
    $items = @($Data)
    if ($items.Count -eq 0) {
        Write-Host " No findings" -ForegroundColor Green
    } else {
        $items | Format-Table -AutoSize -Wrap | Out-String -Width 250 | Write-Host
    }
    $script:summary[$Key] = $items.Count
}

Write-Host "Collecting data, please wait..." -ForegroundColor Yellow

# Fetch once, reused in several sections
$allSPs  = Get-MgServicePrincipal -All
$allApps = Get-MgApplication -All
$roleNames = @{}
Get-MgRoleManagementDirectoryRoleDefinition -All | ForEach-Object { $roleNames[$_.Id] = $_.DisplayName }
$assignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal

# 1. SkyKick / ConnectWise apps
$r1 = $allSPs | Where-Object {
    $_.DisplayName -match 'SkyKick|ConnectWise' -or $_.AppOwnerOrganizationId -eq $skykickTid
} | ForEach-Object {
    [pscustomobject]@{
        Name    = $_.DisplayName
        AppId   = $_.AppId
        Enabled = if ($_.AccountEnabled) { 'YES - disable now!' } else { 'No' }
    }
}
Show-Section 1 "SkyKick / ConnectWise apps in tenant" $r1 'SkyKick/ConnectWise apps'
$summary['  of which still enabled'] = @($r1 | Where-Object { $_.Enabled -like 'YES*' }).Count

# 2. Apps (service principals) with a directory role
$r2 = $assignments | Where-Object {
    $_.Principal.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.servicePrincipal'
} | ForEach-Object {
    [pscustomobject]@{
        Role  = $roleNames[$_.RoleDefinitionId]
        App   = $_.Principal.AdditionalProperties.displayName
        AppId = $_.Principal.AdditionalProperties.appId
    }
} | Sort-Object Role, App
Show-Section 2 "Apps with a directory role (review!)" $r2 'Apps with admin role'

# 3. All Global Administrators
$gaId = '62e90394-69f5-4237-9190-012177145e10'
$r3 = $assignments | Where-Object { $_.RoleDefinitionId -eq $gaId } | ForEach-Object {
    $p = $_.Principal.AdditionalProperties
    [pscustomobject]@{
        Type        = ($p.'@odata.type' -replace '#microsoft.graph.','')
        Name        = $p.displayName
        UPN_or_AppId = if ($p.userPrincipalName) { $p.userPrincipalName } else { $p.appId }
    }
} | Sort-Object Type, Name
Show-Section 3 "Global Administrators" $r3 'Global Admins'

# 4. New secrets/certificates since cutoff date
$r4 = foreach ($obj in $allApps + $allSPs) {
    $kind = if ($obj -is [Microsoft.Graph.PowerShell.Models.MicrosoftGraphApplication]) { 'App registration' } else { 'Enterprise app' }
    foreach ($c in @($obj.PasswordCredentials) + @($obj.KeyCredentials)) {
        if ($c -and $c.StartDateTime -ge $since) {
            [pscustomobject]@{
                Object  = $obj.DisplayName
                Kind    = $kind
                AppId   = $obj.AppId
                Secret  = $c.DisplayName
                Created = $c.StartDateTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm')
                KeyId   = $c.KeyId
            }
        }
    }
}
$r4 = $r4 | Sort-Object Created
Show-Section 4 "New secrets/certificates since $($since.ToString('yyyy-MM-dd'))" $r4 'New secrets/certs'

# 5. New users since cutoff date
$r5 = Get-MgUser -All -Property DisplayName,UserPrincipalName,CreatedDateTime,AccountEnabled |
    Where-Object { $_.CreatedDateTime -ge $since } | Sort-Object CreatedDateTime | ForEach-Object {
        [pscustomobject]@{
            Name    = $_.DisplayName
            UPN     = $_.UserPrincipalName
            Created = $_.CreatedDateTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm')
            Enabled = $_.AccountEnabled
        }
    }
Show-Section 5 "New users since $($since.ToString('yyyy-MM-dd'))" $r5 'New users'

# 6. Audit log: actions performed by apps
$r6 = Get-MgAuditLogDirectoryAudit -All -Filter "activityDateTime ge $($since.ToString('yyyy-MM-dd'))T00:00:00Z" |
    Where-Object { $_.InitiatedBy.App.DisplayName } | Sort-Object ActivityDateTime | ForEach-Object {
        [pscustomobject]@{
            Time   = $_.ActivityDateTime.ToLocalTime().ToString('yyyy-MM-dd HH:mm')
            Action = $_.ActivityDisplayName
            ByApp  = $_.InitiatedBy.App.DisplayName
            Target = ($_.TargetResources.DisplayName | Where-Object { $_ }) -join ', '
        }
    }
Show-Section 6 "Audit log: actions by apps since $($since.ToString('yyyy-MM-dd'))" $r6 'Audit actions by apps'

# --- Summary ---
Write-Host ""
Write-Host ("=" * 90) -ForegroundColor DarkGray
Write-Host " SUMMARY" -ForegroundColor Cyan
Write-Host ("=" * 90) -ForegroundColor DarkGray
foreach ($k in $summary.Keys) {
    $color = if ($summary[$k] -gt 0 -and $k -notin 'Global Admins','SkyKick/ConnectWise apps') { 'Yellow' } else { 'Gray' }
    Write-Host (" {0,-35} {1}" -f $k, $summary[$k]) -ForegroundColor $color
}
Write-Host ""
Write-Host " Note: check service principal sign-ins (IP 144.172.64.128) in Entra -> Sign-in logs." -ForegroundColor DarkGray
