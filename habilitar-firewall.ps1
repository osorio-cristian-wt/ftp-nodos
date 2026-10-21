#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Abre en el Firewall de Windows el puerto TCP de ztftp (entrada).
.EXAMPLE
    .\habilitar-firewall.ps1
.EXAMPLE
    .\habilitar-firewall.ps1 -RemoteAddress 10.147.17.0/24   # solo desde tu red ZeroTier
.EXAMPLE
    .\habilitar-firewall.ps1 -Quitar
#>
param(
    [int]$Port = 9777,
    [string]$RemoteAddress = "Any",
    [switch]$Quitar
)

$name = "ztftp-$Port"

Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule

if ($Quitar) {
    Write-Host "Regla '$name' eliminada."
    return
}

# Profile Any: las redes ZeroTier suelen clasificarse como "Public".
New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort $Port -RemoteAddress $RemoteAddress -Profile Any | Out-Null

Write-Host "Regla '$name' creada: TCP $Port entrante desde $RemoteAddress."
