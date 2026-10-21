#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Registra `ztftp serve` como tarea programada: arranca con Windows (sin
    necesidad de iniciar sesion) y se reinicia sola si falla.
.EXAMPLE
    .\instalar-servicio.ps1
.EXAMPLE
    .\instalar-servicio.ps1 -Root D:\compartido
.EXAMPLE
    .\instalar-servicio.ps1 -Quitar
#>
param(
    [string]$Root = "~",
    [switch]$Quitar
)

$task = "ztftp"

if ($Quitar) {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Tarea '$task' eliminada."
    return
}

$python = (Get-Command python -ErrorAction Stop).Source
$script = Join-Path $PSScriptRoot "ztftp.py"
$log    = Join-Path $env:USERPROFILE ".ztftp.log"

# Se ejecuta con el usuario actual para que use su ~/.ztftp.json y su home.
$arg = "/c `"`"$python`" `"$script`" serve --root `"$Root`" >> `"$log`" 2>&1`""
$action    = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $arg
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Limited
# Si ZeroTier aun no tiene IP al arrancar, serve sale con error y se reintenta.
$settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $task

Write-Host "Tarea '$task' instalada y iniciada. Log: $log"
Write-Host "Estado:  Get-ScheduledTask $task | Get-ScheduledTaskInfo"
