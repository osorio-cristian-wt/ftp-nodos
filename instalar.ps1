#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Deja este nodo Windows listo para usar ztftp: instala el comando `ztftp`,
    escribe la config, abre el firewall, registra el demonio como tarea
    programada (arranca con Windows y se reinicia si falla) y activa el Tab.
.PARAMETER Token
    Token compartido de la red. Sin el, se genera uno (primer nodo) y se muestra
    al final para pasarselo a los demas nodos.
.PARAMETER Nodo
    Alias de nodos como NOMBRE=IP (ej. pc1=10.147.17.5 pc2=10.147.17.8).
.PARAMETER Root
    Directorio que expone este nodo (default: el 'root' de la config, o el home).
.PARAMETER RemoteAddress
    Origenes permitidos en el firewall (default: las subredes ZeroTier de este nodo).
.PARAMETER Quitar
    Desinstala todo (la config con el token se conserva).
.EXAMPLE
    .\instalar.ps1 -Nodo pc1=10.147.17.5,pc2=10.147.17.8 -Root C:\repos
.EXAMPLE
    .\instalar.ps1 -Token <token-del-primer-nodo> -Nodo pc1=10.147.17.5,pc2=10.147.17.8 -Root C:\repos
.EXAMPLE
    .\instalar.ps1 -Quitar
#>
param(
    [string]$Token,
    [string[]]$Nodo,
    [string]$Root,
    [string]$RemoteAddress,
    [int]$Port,
    [switch]$Quitar
)

$task       = "ztftp"
$script     = Join-Path $PSScriptRoot "ztftp.py"
$completion = Join-Path $PSScriptRoot "ztftp-completion.ps1"
$profLine   = ". `"$completion`""
$config     = Join-Path $env:USERPROFILE ".ztftp.json"
$log        = Join-Path $env:USERPROFILE ".ztftp.log"

function Remove-Rules { Get-NetFirewallRule -DisplayName "ztftp*" -ErrorAction SilentlyContinue | Remove-NetFirewallRule }

if ($Quitar) {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Rules
    python -m pip uninstall -y ztftp
    if (Test-Path $PROFILE) { (Get-Content $PROFILE) | Where-Object { $_ -ne $profLine } | Set-Content $PROFILE }
    Write-Host "ztftp desinstalado. Se conservo $config (contiene el token)."
    return
}

# --- Python real (no el alias de la Microsoft Store) -------------------------
$python = (& python -c "import sys; print(sys.executable)") 2>$null
if ($LASTEXITCODE -ne 0 -or -not $python -or -not (Test-Path $python)) {
    throw "No encuentro Python 3.8+ en el PATH. Instalalo desde python.org y reintenta."
}

# --- IPs y subredes de ZeroTier (zerotier-cli exige administrador) -----------
function Get-Subnet($cidr) {
    $ip, $bits = $cidr -split "/"
    $b = [Net.IPAddress]::Parse($ip).GetAddressBytes()
    for ($i = 0; $i -lt 4; $i++) {
        $keep = [Math]::Max(0, [Math]::Min(8, [int]$bits - 8 * $i))
        $b[$i] = $b[$i] -band ((255 -shl (8 - $keep)) -band 255)
    }
    "$($b -join '.')/$bits"
}
$cidrs = @()
try {
    $nets = (& zerotier-cli -j listnetworks | Out-String) | ConvertFrom-Json
    $cidrs = @($nets | Where-Object { $_.status -eq "OK" } |
        ForEach-Object { $_.assignedAddresses } | Where-Object { $_ -and $_ -notmatch ":" })
} catch { }
if (-not $cidrs) {
    throw "Este nodo no tiene IP de ZeroTier. Unilo a la red y autorizalo en ZeroTier Central (zerotier-cli listnetworks)."
}
$bindIps = @($cidrs | ForEach-Object { ($_ -split "/")[0] })
$subnets = @($cidrs | ForEach-Object { Get-Subnet $_ } | Select-Object -Unique)

# --- 1. Comando ztftp --------------------------------------------------------
& $python -m pip install --user -q --disable-pip-version-check -e $PSScriptRoot
if ($LASTEXITCODE -ne 0) { throw "pip fallo al instalar el comando ztftp" }
$scriptsDir = & $python -c "import sysconfig; print(sysconfig.get_path('scripts', 'nt_user'))"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ";") -notcontains $scriptsDir) {
    $newPath = if ($userPath) { "$userPath;$scriptsDir" } else { $scriptsDir }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "Agregado al PATH de usuario: $scriptsDir"
}

# --- 2. Config (token, alias, raiz, IPs donde escucha) -----------------------
$initArgs = @("init")
foreach ($ip in $bindIps) { $initArgs += @("--bind", $ip) }
if ($Token) { $initArgs += @("--token", $Token) }
if ($Root)  { $initArgs += @("--root", $Root) }
if ($Port)  { $initArgs += @("--port", $Port) }
foreach ($n in $Nodo) { $initArgs += @("--node", $n) }
& $python $script @initArgs
if ($LASTEXITCODE -ne 0) { throw "no se pudo escribir $config" }
$cfg = Get-Content $config -Raw | ConvertFrom-Json
$puerto = [int]$cfg.port

# --- 3. Firewall -------------------------------------------------------------
Remove-Rules
$remote = if ($RemoteAddress) { $RemoteAddress } else { $subnets }
# Perfil Any: las redes ZeroTier suelen clasificarse como "Publica".
New-NetFirewallRule -DisplayName "ztftp" -Direction Inbound -Action Allow -Protocol TCP `
    -LocalPort $puerto -RemoteAddress $remote -Profile Any | Out-Null
Write-Host "Firewall: TCP $puerto entrante desde $($remote -join ', ')"

# --- 4. Demonio como tarea programada ----------------------------------------
# Corre con tu usuario (usa tu ~/.ztftp.json), sin sesion abierta. Las IPs de
# ZeroTier salen de la config porque zerotier-cli no funciona sin elevar.
$arg       = "/c `"`"$python`" `"$script`" serve >> `"$log`" 2>&1`""
$action    = New-ScheduledTaskAction -Execute "cmd.exe" -Argument $arg
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName $task -Action $action -Trigger $trigger -Principal $principal -Settings $settings | Out-Null
Start-ScheduledTask -TaskName $task

# --- 5. Autocompletado en PowerShell -----------------------------------------
if (-not (Test-Path $PROFILE)) { New-Item -ItemType File -Force $PROFILE | Out-Null }
if (-not (Select-String -Path $PROFILE -SimpleMatch -Pattern $profLine -Quiet)) {
    Add-Content $PROFILE "`n# ztftp: autocompletado`n$profLine"
}

# --- Verificacion ------------------------------------------------------------
$escucha = $false
for ($i = 0; $i -lt 15 -and -not $escucha; $i++) {
    Start-Sleep 1
    $escucha = [bool](Get-NetTCPConnection -LocalPort $puerto -State Listen -ErrorAction SilentlyContinue)
}
Write-Host ""
if ($escucha) {
    Write-Host "OK: demonio escuchando en $($bindIps -join ', '):$puerto" -ForegroundColor Green
} else {
    Write-Warning "El demonio no esta escuchando todavia. Revisa el log: $log"
}
Write-Host "Abri una terminal nueva y proba:  ztftp ls <nodo>:."
if (-not $Token) {
    Write-Host ""
    Write-Host "Token de la red: $($cfg.token)" -ForegroundColor Yellow
    Write-Host "En los demas nodos corre:  .\instalar.ps1 -Token $($cfg.token) -Nodo <nombre>=<ip> ..."
}
