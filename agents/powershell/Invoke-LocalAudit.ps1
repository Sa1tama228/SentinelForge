<#
.SYNOPSIS
    SentinelForge agent — quick local hardening/audit checks on a Windows host.

.DESCRIPTION
    Defensive only. Reports listening TCP ports, firewall state, SMBv1 status
    and members of the local Administrators group. Run elevated.

.EXAMPLE
    .\Invoke-LocalAudit.ps1
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "SilentlyContinue"

Write-Host "=== SentinelForge :: Local audit ===" -ForegroundColor Cyan

Write-Host "`n[1] Listening TCP ports" -ForegroundColor Yellow
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Sort-Object LocalPort | Format-Table -AutoSize

Write-Host "[2] Windows Firewall profiles" -ForegroundColor Yellow
Get-NetFirewallProfile |
    Select-Object Name, Enabled | Format-Table -AutoSize

Write-Host "[3] SMBv1 status (should be Disabled)" -ForegroundColor Yellow
$smb = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
if ($smb) {
    Write-Host "SMB1Protocol: $($smb.State)"
} else {
    $cfg = Get-SmbServerConfiguration
    Write-Host "EnableSMB1Protocol: $($cfg.EnableSMB1Protocol)"
}

Write-Host "[4] Local Administrators" -ForegroundColor Yellow
$adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
$adsi.Children | Where-Object { $_.SchemaClassName -eq "group" -and $_.Name -eq "Administrators" } |
    ForEach-Object { $_.Invoke("Members") } |
    ForEach-Object { ([adsi]$_).Path -replace "WinNT://","" }

Write-Host "`nAudit complete." -ForegroundColor Green
