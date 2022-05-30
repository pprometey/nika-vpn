  <#
  .SYNOPSIS
 Installing and configuring the Nika-VPN client
  .DESCRIPTION
  .\install-windows-client.ps1 <VPN server remote public IPv4 address>
  or
  .\install-windows-client.ps1 <VPN server remote public IPv4 address> <VPN tunnel remote port>
  .EXAMPLE
    .\install-windows-client.ps1 10.10.10.10
  .EXAMPLE
    .\install-windows-client.ps1 10.10.10.10 51820 -LocalPort 9191
  #>
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory=$True,
      Position=0,
      ValueFromPipelineByPropertyName,
      HelpMessage='VPN server remote public IP address')]
    [string]
    [ValidatePattern("(^[0-2][0-5]{1,2}?\.|^[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?$|[3-9][0-9]?$)")]
    $VpnHost,
    [Parameter(Mandatory=$False,
      Position=1,
      ValueFromPipelineByPropertyName,
      HelpMessage='VPN tunnel remote port, by default [51820]')]
    [int32]
    [ValidateRange(0,65000)]
    $VpnPort=51820,
    [Parameter(Mandatory=$False,
      HelpMessage='Installation directory')]
    [string]
    $DestanationDir="${HOME}\.wireguard",
    [Parameter(Mandatory=$False,
      HelpMessage='Remote tunnel port, by default [443]')]
    [int32]
    [ValidateRange(0,65000)]
    $TunnelPort=443,
    [Parameter(Mandatory=$False,
      HelpMessage='Tunnel local port, by default [9999]')]
    [int32]
    [ValidateRange(0,65000)]
    $LocalPort=9999,
    [Parameter(Mandatory=$False,
      HelpMessage='UDP forward timeout in seconds after which the connection is closed, by default -1 (no timeout)')]
    [int32]
    [ValidateRange(-1,[int32]::MaxValue)]
    $Timeout=-1,
    [Parameter(Mandatory=$False,
      HelpMessage='Local IP address of Pi-Hole ad blocker, by default [10.43.0.3]')]
    [string]
    [ValidatePattern("(^[0-2][0-5]{1,2}?\.|^[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?\.|[3-9][0-9]?\.)([0-2][0-5]{1,2}?$|[3-9][0-9]?$)")]
    $VpnDns="10.43.0.3"
  )

$InformationPreference = "Continue"

$TunnelDataFile = Join-Path $DestanationDir "tunneldata.json"
Write-Progress "Saving the tunnel settings file to $TunnelDataFile"

$TunnelData = @{
  VpnHost = $VpnHost
  TunnelPort = $TunnelPort
  LocalPort = $LocalPort
  VpnPort = $VpnPort
  Timeout = $Timeout
  VpnDns = $VpnDns
}

$TunnelData | ConvertTo-Json | Set-Content -Path $TunnelDataFile

Write-Progress "Installing wstunnel to $DestanationDir"
$wstunnelUrl = "https://github.com/erebe/wstunnel/releases/download/v4.1/wstunnel-windows-x64.exe.zip"
$tempZipPath = Join-Path ([io.path]::GetTempPath()) "$(New-Guid).zip"
try {
  Write-Progress "Downloading wstunnel"
  Invoke-RestMethod -useb $wstunnelUrl -OutFile $tempZipPath
  Write-Progress "Installing wstunnel"
  Expand-Archive -Path $tempZipPath -DestinationPath $DestanationDir -Force
}
catch
{
  throw "An error occurred while downloading and installing wstunnel"
}
finally
{
  Remove-Item $tempZipPath -force -ErrorAction SilentlyContinue
}

Write-Progress "Installing wstunnel script to $DestanationDir"
$wstunnelScriptUrl = "https://raw.githubusercontent.com/pprometey/nika-vpn/main/clients/windows/wstunnel.ps1"
$wstunnelScriptPath = Join-Path $DestanationDir "wstunnel.ps1"
try {
  Write-Progress "Downloading wstunnel"
  Invoke-RestMethod -useb $wstunnelScriptUrl -OutFile $wstunnelScriptPath
}
catch
{
  throw "An error occurred while downloading wstunnel script file"
}


Write-Progress "Configuring Wireguard to activate the PreUp, PostUp, PreDown, PostDown parameters in the tunnel configuration"
$ActivateDangerousScriptExecutionSplat = @{
  Path = "hklm:\Software\WireGuard"
  Name = "DangerousScriptExecution"
  PropertyType = 'DWord'
  Value = 1
  ErrorAction = 'SilentlyContinue'
}
New-ItemProperty @ActivateDangerousScriptExecutionSplat

Write-Progress  "Restarting the Wireguard Service"
Get-Service WireGuardManager | Restart-Service -Verbose


function Log-Info($text)
{
    Write-Host -fore green $text
}

Log-Info "=========================================================================="
Log-Info ""
Log-Info "Setup completed!"
Log-Info ""
Log-Info "Edit the VPN connection configuration through Wireguard"
Log-Info "In the [Interface] section, add the lines:"
Log-Info "[Interface]"
Log-Info "..."
Log-Info "PreUp = powershell.exe -File `"$wstunnelScriptPath`" -PreUp "
Log-Info "PostUp = powershell.exe -File `"$wstunnelScriptPath`" -PostUp"
Log-Info "PreDown = powershell.exe -File `"$wstunnelScriptPath`" -PreDown"
Log-Info "Table = off"
Log-Info ""
Log-Info "In the [Peer] section, change the Endpoint parameter to the value:"
Log-Info "Endpoint = 127.0.0.1:$LocalPort"
Log-Info ""
Log-Info "After these steps, connect the VPN and you can follow the link:"
Log-Info "https://ipleak.net to check the privacy of your connection"
Log-Info ""
Log-Info "=========================================================================="
