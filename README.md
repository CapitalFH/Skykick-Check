# skykick-tenant-check

Small PowerShell script I put together on Saturday morning after the ConnectWise Cloud Backup (ex SkyKick) incident. I wanted a quick way to see if a tenant was touched, without clicking through Entra for every check. Sharing it in case it saves someone else some time.

The tenant queries only read. The script does not disable, delete or change tenant objects. It may install missing Graph modules locally, prompts for Graph sign-in/consent, and writes a local report.

## What it checks

1. SkyKick / ConnectWise name or vendor-owner matches and their enabled state; verify the exact product and owner before taking action
2. Service principals with direct directory-role assignments
3. Direct Global Administrator assignments, including assigned groups (members and PIM eligibility are not expanded)
4. Current app/SP secrets and certificates whose **validity starts** in the selected window
5. Current users created in the selected window
6. Directory audit records in that window, **including user actors and apps without a display name**, with event IDs, actor IDs, targets and results

The default window starts at **13 Oct 2026 00:00 UTC** and ends at the fixed start-of-run time. All displayed timestamps and saved bounds are UTC. A failed read/page makes its dependent checks **Unavailable**, with an unknown count; it is never reported as zero findings. Other successful checks are still saved, and the script throws after saving an incomplete report.

Section 4 is an inventory filter, not a credential-creation detector. Microsoft's [passwordCredential](https://learn.microsoft.com/en-us/graph/api/resources/passwordcredential?view=graph-rest-1.0) and [keyCredential](https://learn.microsoft.com/en-us/graph/api/resources/keycredential?view=graph-rest-1.0) define `startDateTime` as the time the credential becomes valid. A credential added recently with an older validity date will not appear in this table. Review section 6 and its saved `TargetResources.ModifiedProperties` for credential changes, including credentials later removed. All current credential metadata is retained in the JSON, without password hints, secret values or certificate bytes.

Service principal sign-ins from the attacker IP (144.172.64.128) are not in the script. Check those in Entra > Sign-in logs > Service principal sign-ins.

## What you need

- Windows PowerShell 5.1 or PowerShell 7
- Microsoft Graph PowerShell modules. The script installs the ones it needs (CurrentUser scope) if they are missing.
- An account with at least Global Reader
- Consent for: Directory.Read.All, AuditLog.Read.All, RoleManagement.Read.Directory, Application.Read.All

## How to run

```powershell
Unblock-File .\skykick-check.ps1
.\skykick-check.ps1
```

A login window pops up; sign in to the tenant you want to check. The actual tenant and account are printed and saved. To require a specific tenant and choose a fixed window:

```powershell
.\skykick-check.ps1 -TenantId 'YOUR-TENANT-GUID' `
    -SinceUtc '2026-10-13T00:00:00Z' -UntilUtc '2026-10-17T00:00:00Z' `
    -OutputDirectory '.\incident-check-01'
```

Replace `YOUR-TENANT-GUID` with the tenant GUID. A tenant mismatch or invalid/future window stops before collection. Offset timestamps are normalized to UTC. The output directory must not already exist, so previous evidence is not replaced.

If the script is blocked by execution policy:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Without `-OutputDirectory`, a unique `skykick-check-*` directory is created in the current location. `report.json` contains selected SDK data, per-collection status/errors/times, query bounds, script hash and the six summaries; `report.sha256` hashes the exact saved JSON. These are SDK snapshots, not original HTTP responses or independently verified complete source logs. No tokens are saved. The report contains tenant/user information: keep it in your incident evidence store, **not in a public issue or PR**. Default output folders are gitignored; custom output paths need equivalent care.

`-All` requests SDK pagination, but a completed read does not prove historical coverage: retention, ingestion delays and permissions still apply. Missing/deleted objects cannot be reconstructed from current inventory alone.

The script does not collect PIM eligibility, membership of role-assigned groups, federated credentials, vendor-home-tenant credentials, application/delegated permission grants, Graph API request logs, mailbox/file access or provider-side backup downloads. A clean summary cannot establish absence of access or exfiltration.

## If you find something

- Preserve the relevant records and establish the exact identity, actor, time and authorization before remediation. A name match, enabled app or unfamiliar role alone is not proof of compromise; other ConnectWise products may match the name filter.
- Disabling an affected SkyKick app does not remove credentials added to other apps. Investigate credential changes and remove confirmed unauthorized credentials through your incident process (the KeyId is in section 4/audit details).
- Investigate unfamiliar role assignments and accounts; contain confirmed unauthorized access through your incident process.
- Turn on Microsoft Graph activity logs if you haven't yet.
- Keep an eye on status.connectwise.com before turning the backup app back on.

## Disclaimer

No guarantees. A clean result does not prove the tenant is clean, and something showing up is not always malicious. Use your own judgement and check the findings by hand.

Read the script before you run it. That goes for any script you find online, including this one.

Improvements and fixes are welcome, open an issue or PR.

## Offline regression tests

```powershell
powershell.exe -NoProfile -File .\tests\Invoke-OfflineTests.ps1
pwsh -NoProfile -File .\tests\Invoke-OfflineTests.ps1
```

These use synthetic SDK fixtures, require no Graph modules/Pester, and make no network or tenant calls. They exercise actor preservation, UTC bounds, credential-date labeling, metadata filtering, pagination failures, dependent-check status, empty results, tenant mismatch and evidence overwrite protection. Test artifacts go to a unique local temporary directory. Live SDK/tenant validation remains separate.
