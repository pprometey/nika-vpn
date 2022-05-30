[CmdletBinding(DefaultParameterSetName = "PreDown")]
param (
    # WireGuard Interface
    [Parameter(Position = 0)]
    [string]
    $WireGuardInterfaceName = $env:WIREGUARD_TUNNEL_NAME,
    # Pre Up Switch
    [Parameter(ParameterSetName = "PreUp")]
    [switch]
    $PreUp,
    # Post Up Switch
    [Parameter(ParameterSetName = "PostUp")]
    [switch]
    $PostUp,
    # PreDown Up Switch
    [Parameter(ParameterSetName = "PreDown")]
    [switch]
    $PreDown
)

$InformationPreference = "Continue"

function Get-Script-Directory {
    $scriptInvocation = (Get-Variable MyInvocation -Scope 1).Value
    return Split-Path $scriptInvocation.MyCommand.Path
}

$WireGuardInterface = Get-NetAdapter -Name $WireGuardInterfaceName

$ScriptPath = (Get-Script-Directory)
$TunnelDataFile = Join-Path $ScriptPath "tunneldata.json"
$WstunnelPath = Join-Path $ScriptPath "wstunnel.exe"
$TunnelData = Get-Content -Path $TunnelDataFile -Raw | ConvertFrom-Json

function IfNull($value, $defaultValue) { if ($null -ne $value) { $value } else { $defaultValue } }
function IfNullThrow($value, $errorMessage) { if ($null -ne $value) { $value } else { throw  $errorMessage } }

[string]$VpnHost = IfNullThrow $TunnelData.VpnHost "VPN server IP address must not be empty"
[int]$TunnelPort = IfNull $TunnelData.TunnelPort 443
[int]$LocalPort = IfNull $TunnelData.LocalPort 9999
[int]$VpnPort = IfNull $TunnelData.VpnPort 51820
[int]$Timeout = IfNull $TunnelData.Timeout -1
[string]$VpnDns = IfNull $TunnelData.VpnDns "10.43.0.3"

# Start/Stop wstunnel
Write-Information -MessageData "Taking care of wstunnel"
switch ($PSCmdlet.ParameterSetName) {
    "PreUp" {
        Start-Process -FilePath $WstunnelPath -ArgumentList `
            "--quiet", `
            "--udp", `
            "--udpTimeoutSec ${Timeout}", `
            "-L ${LocalPort}:127.0.0.1:${VpnPort}", `
            "wss://${VpnHost}:${TunnelPort}" `
            -PassThru
    }
    "PreDown" {
    #   Get-Process -Name "wstunnel" | Stop-Process
    }
    Default {}
}

# Add/Remove route to WireGuard interface
$DefaultNetRouteSplat = @{
    InterfaceAlias    = $WireGuardInterface.InterfaceAlias
    DestinationPrefix = "0.0.0.0/0"
    RouteMetric       = 35
    Confirm           = $false
}
Write-Information -MessageData "Taking care of Default Route"
switch ($PSCmdlet.ParameterSetName) {
    "PostUp" { New-NetRoute @DefaultNetRouteSplat | Out-Null }
    "PreDown" { Remove-NetRoute @DefaultNetRouteSplat | Out-Null }
    Default {}
}

# Add/Remove DNS server to WireGuard interface
$setDnsClientServerAddressSplat = @{
    InterfaceIndex = Get-NetRoute | ForEach-Object { Process { If (!$_.RouteMetric) { $_.ifIndex } } }
}
Write-Information -MessageData "Taking care of DNS"
switch ($PSCmdlet.ParameterSetName) {
    "PostUp" {
        Set-DnsClientServerAddress @setDnsClientServerAddressSplat -ServerAddresses "${VpnDns}"
    }
    "PreDown" {
        Set-DnsClientServerAddress @setDnsClientServerAddressSplat -ResetServerAddresses
    }
    Default {}
}
