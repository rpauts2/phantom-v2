#Requires -RunAsAdministrator
# Phantom v2 — установка службой Windows через Scheduled Task (автозапуск).
# Использование (PowerShell от админа, из корня C:\phantom):
#   .\deploy\install-service.ps1
# Удаление:
#   .\deploy\install-service.ps1 -Uninstall
param([switch]$Uninstall)
$ErrorActionPreference = "Stop"
$TaskName = "PhantomV2"
$Dir = "C:\phantom"
$Exe = "$Dir\phantom.exe"
$Args = "-config $Dir\config.yaml -phishlets $Dir\configs\phishlets"

if ($Uninstall) {
    schtasks /Delete /TN $TaskName /F 2>$null
    Write-Host "task removed"
    exit 0
}
if (-not (Test-Path $Exe)) {
    Write-Error "missing $Exe (build first: go build -o phantom.exe ./cmd/phantom)"
}
$Action = New-ScheduledTaskAction -Execute $Exe -Argument $Args -WorkingDirectory $Dir
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3
Invoke-RestMethod http://127.0.0.1:8080/health
Write-Host "service running"
