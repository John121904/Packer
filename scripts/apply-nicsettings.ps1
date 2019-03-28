
#disable ipv6 on primary nic
$nic = get-netadapter
Disable-NetAdapterBinding –InterfaceAlias $nic.name –ComponentID ms_tcpip6
Disable-NetAdapterBinding –Name $nic.name –ComponentID ms_tcpip6

#rename ethernet adapter
Get-NetAdapter -Name * | Rename-NetAdapter -NewName "Primary Network Connection"

#enable netbios and disable wins
$adapters=(gwmi win32_networkadapterconfiguration )
 Foreach($adapter in $adapters)
 {
    Write-Host $adapter
    $adapter.settcpipnetbios(1)
  }
  $nics=([wmiclass]'Win32_NetworkAdapterConfiguration')
  Foreach($nic in $nics){
  Write-Host $adapter
  $nic.enablewins($false,$false)
  }


