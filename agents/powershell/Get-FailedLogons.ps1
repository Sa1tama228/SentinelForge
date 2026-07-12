[CmdletBinding()]
param(
    [int]$Hours = 24
)

$ErrorActionPreference = "Stop"

Write-Host "=== SentinelForge :: Failed logons (last $Hours h) ===" -ForegroundColor Cyan

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 4625
        StartTime = (Get-Date).AddHours(-$Hours)
    } -ErrorAction Stop
} catch [System.Exception] {
    if ($_.Exception.Message -match "No events were found") {
        Write-Host "No 4625 events in range." -ForegroundColor Green
        return
    }
    throw
}

if (-not $events) {
    Write-Host "No failed logons found." -ForegroundColor Green
    return
}

$rows = $events | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $d = @{}
    foreach ($n in $xml.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
    [pscustomobject]@{
        Time      = $_.TimeCreated
        Target    = $d.TargetUserName
        SourceIp  = $d.IpAddress
        LogonType = $d.LogonType
    }
}

$rows | Group-Object SourceIp | Sort-Object Count -Descending |
    Select-Object Count, Name | Format-Table -AutoSize

Write-Host "`nMost-targeted accounts:" -ForegroundColor Yellow
$rows | Group-Object Target | Sort-Object Count -Descending |
    Select-Object -First 10 Count, Name | Format-Table -AutoSize
