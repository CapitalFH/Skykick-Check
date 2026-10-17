# skykick-tenant-check

Small PowerShell script I put together on Saturday morning after the ConnectWise Cloud Backup (ex SkyKick) incident. I wanted a quick way to see if a tenant was touched, without clicking through Entra for every check. Sharing it in case it saves someone else some time.

The script only reads. It does not disable, delete or change anything in your tenant.

## What it checks

1. SkyKick / ConnectWise apps in the tenant, and if they are still enabled
2. Apps (service principals) that have a directory role
3. Everyone with Global Administrator
4. New secrets and certificates on app registrations and enterprise apps since 13 Oct 2026
5. New users since 13 Oct 2026
6. Audit log entries that were done by an app (not a user) since 13 Oct 2026

At the end you get a short summary with counts. Anything above 0 in yellow is worth a look.

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

A login window pops up, sign in to the tenant you want to check.

If the script is blocked by execution policy:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Want a different start date? Change `$since` at the top of the script.

## If you find something

- Disabling the SkyKick app is not enough. Credentials that were added to other apps keep working, so remove those (the KeyId is in section 4).
- Remove role assignments you don't recognise.
- Block and remove accounts you didn't create, and revoke their sessions.
- Turn on Microsoft Graph activity logs if you haven't yet.
- Keep an eye on status.connectwise.com before turning the backup app back on.

## Disclaimer

No guarantees. A clean result does not prove the tenant is clean, and something showing up is not always malicious. Use your own judgement and check the findings by hand.

Read the script before you run it. That goes for any script you find online, including this one.

Improvements and fixes are welcome, open an issue or PR.
