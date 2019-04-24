:: ***********************************************************
:: *** Carlson Wagonlit Travel Windows 2016 Build Settings ***
:: ***********************************************************

@echo off

:: Create Directory
mkdir C:\install\log

:: Disable UAC
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 0 /f

:: Relax PowerShell Execution Policy
powershell.exe set-executionpolicy bypass -Force

:: Install Windows 2016 Features
::powershell.exe a:/Win2016Features.ps1

:: Set boot delay to 10 seconds
bcdedit /timeout 10

:: Configure SNMP service
REG ADD "HKLM\System\CurrentControlSet\Services\SNMP\Parameters" /v "EnableAuthenticationTraps" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" /v "Kpwx5FKEUx3r3Y8vygpN" /t REG_DWORD /d "4" /f
:: REG ADD "HKLM\System\CurrentControlSet\Services\SNMP\Parameters\TrapConfiguration\XnNVvqmTYyH2w13krLXP" /v "1" /t REG_SZ /d "10.213.252.13" /f
REG DELETE "HKLM\System\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" /f

:: Enable Remote Desktop
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d "0" /f

:: Do not show Server Manager at logon
REG ADD "HKLM\SOFTWARE\Microsoft\ServerManager" /v "DoNotOpenServerManagerAtLogon" /t REG_DWORD /d "1" /f

:: Do not show initial configuration at logon
REG ADD "HKLM\SOFTWARE\Microsoft\ServerManager\Oobe" /v "DoNotOpenInitialConfigurationTasksAtLogon" /t REG_DWORD /d "1" /f

:: Disable Autorun
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "0xFF" /f

:: Disable installing with elevated privileges
REG ADD "HKLM\Software\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d "0" /f

:: Set Event Log sizes and retention behavior
REG ADD "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" /v "MaxSize" /t REG_DWORD /d "0x30000" /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application" /v "MaxSize" /t REG_DWORD /d "0x8000" /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\EventLog\System" /v "MaxSize" /t REG_DWORD /d "0x8000" /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security" /v "Retention" /t REG_SZ /d "0" /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application" /v "Retention" /t REG_SZ /d "0" /f
REG ADD "HKLM\Software\Policies\Microsoft\Windows\EventLog\System" /v "Retention" /t REG_SZ /d "0" /f

:::: Configure "My Computer" icon and place on desktop
:: Default user
REG LOAD HKLM\defuhive "%systemdrive%\users\default user\ntuser.dat"
REM *** Add My Computer Icon to Desktop
REG ADD "HKLM\defuhive\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
REM *** Change My Computer Icon Title to Computer Name
REG ADD "HKLM\defuhive\Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /ve /t REG_EXPAND_SZ /d ^%%computername^%% /f
REG ADD "HKLM\defuhive\Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /v "LocalizedString" /t REG_EXPAND_SZ /d "@%SystemRoot%\system32\shell32.dll,-9216@1033,%%ComputerName%%" /f
:: Current user
REM *** Add My Computer Icon to Desktop
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
REM *** Change My Computer Icon Title to Computer Name
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /ve /t REG_EXPAND_SZ /d ^%%computername^%% /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /v "LocalizedString" /t REG_EXPAND_SZ /d "@%SystemRoot%\system32\shell32.dll,-9216@1033,%%ComputerName%%" /f

:: Configure Explorer view settings
REG ADD "HKLM\defuhive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
REG ADD "HKLM\defuhive\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
REG ADD "HKLM\defuhive\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" /v "FullPath" /t REG_DWORD /d "1" /f
REG UNLOAD HKLM\defuhive 
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" /v "FullPath" /t REG_DWORD /d "1" /f

:: Disable DR Watson errors
REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug" /v "Debugger" /t REG_SZ /d "" /f

:: Remove WSUS settings
REG DELETE HKLM\SOFTWARE\Policies\Microsoft\windows\WindowsUpdate\AU /v NoAutoRebootWithLoggedOnUsers /f
REG DELETE HKLM\SOFTWARE\Policies\Microsoft\windows\WindowsUpdate\AU /v ScheduledInstallDay /f
REG DELETE HKLM\SOFTWARE\Policies\Microsoft\windows\WindowsUpdate\AU /v ScheduledInstallTime /f

:: RDP Session Properties
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fInheritResetBroken" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fInheritShadow" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fInheritMaxSessionTime" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fInheritMaxDisconnectionTime" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fInheritMaxIdleTime" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fInheritAutoClient" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fPromptForPassword" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fAutoClientDrives" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fAutoClientLpts" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fForceClientLptDef" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fDisableCpm" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fDisableCdm" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fDisableCcm" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "fDisableLPT" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "MaxDisconnectionTime" /t REG_DWORD /d "60000" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "MaxIdleTime" /t REG_DWORD /d "1800000" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "MinEncryptionLevel" /t REG_DWORD /d "3" /f

:: ICA Session Properties (Effective for Citrix servers)
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp" /v "fInheritResetBroken" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp" /v "fInheritReconnectSame" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp" /v "fInheritShadow" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp" /v "fInheritMaxSessionTime" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp" /v "fInheritMaxDisconnectionTime" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp" /v "fInheritMaxIdleTime" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp" /v "fInheritAutoClient" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp" /v "fReconnectSame" /t REG_DWORD /d "1" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp" /v "fAutoClientDrives" /t REG_DWORD /d "0" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp" /v "MaxDisconnectionTime" /t REG_DWORD /d "600000" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp" /v "MaxIdleTime" /t REG_DWORD /d "5400000" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp\AudioConfig" /v "PCMOutputFormat" /t REG_DWORD /d "400" /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\ICA-tcp\AutoClientPrinters" /v "Flags" /t REG_DWORD /d "1" /f

:: Disable printer warnings in event log
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers" /v "EventLog" /t REG_DWORD /d "0" /f

:::: Remove IE Hardening warning screen
:: Default user
REG LOAD HKLM\defuhive "%systemdrive%\Users\Default\ntuser.dat"
REG ADD "HKLM\defuhive\Software\Microsoft\Internet Explorer\Main" /v "IE11RunOnceLastShown" /t REG_DWORD /d "1" /f
REG ADD "HKLM\defuhive\Software\Microsoft\Internet Explorer\Main" /v "IE11RunOncePerInstallCompleted" /t REG_DWORD /d "1" /f
REG ADD "HKLM\defuhive\Software\Microsoft\Internet Explorer\Main" /v "IE11RunOnceCompletionTime" /t REG_BINARY /d "" /f
REG ADD "HKLM\defuhive\Software\Microsoft\Internet Explorer\Main" /v "IE11TourShown" /t REG_DWORD /d "1" /f
REG ADD "HKLM\defuhive\Software\Microsoft\Internet Explorer\Main" /v "IE11TourShownTime" /t REG_BINARY /d "" /f
REG ADD "HKLM\defuhive\Software\Microsoft\Internet Explorer\Main" /v "IE11RunOnceLastShown_TIMESTAMP" /t REG_BINARY /d "" /f
REG ADD "HKLM\defuhive\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "1" /f
REG UNLOAD HKLM\defuhive 
:: Current user
REG ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v "IE11RunOnceLastShown" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v "IE11RunOncePerInstallCompleted" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v "IE11RunOnceCompletionTime" /t REG_BINARY /d "" /f
REG ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v "IE11TourShown" /t REG_DWORD /d "1" /f
REG ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v "IE11TourShownTime" /t REG_BINARY /d "" /f
REG ADD "HKCU\Software\Microsoft\Internet Explorer\Main" /v "IE11RunOnceLastShown_TIMESTAMP" /t REG_BINARY /d "" /f
REG ADD "HKCU\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "1" /f
:: Local Machine
REG ADD "HKLM\Software\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d "1" /f

:: ** Replace sceregvl.inf file so Local Security policy will see the custom registry settings **
:: Take ownership of the file and grant access
takeown /f c:\windows\inf\sceregvl.inf /A
icacls c:\windows\inf\sceregvl.inf /grant administrators:F
:: Rename the original file, save it to a safe place
rename c:\windows\inf\sceregvl.inf sceregvl.inf.original
icacls c:\windows\inf\sceregvl.inf.original /inheritance:d
icacls c:\windows\inf\sceregvl.inf.original /grant[:r] System:RX
icacls c:\windows\inf\sceregvl.inf.original /setowner "NT Service\TrustedInstaller"
icacls c:\windows\inf\sceregvl.inf.original /grant[:r] administrators:RX
:: Replace the file with the Carlson version
copy a:\sceregvl.inf C:\Windows\inf\sceregvl.inf /y
icacls c:\windows\inf\sceregvl.inf /inheritance:d
icacls c:\windows\inf\sceregvl.inf /grant:r System:RX
icacls c:\windows\inf\sceregvl.inf /setowner "NT Service\TrustedInstaller"
icacls c:\windows\inf\sceregvl.inf /grant:r administrators:RX
:: Re-register the scecli.dll for use with the Local Security Policy GUIs
regsvr32 scecli.dll /s
:: Rename temp file so it doesn't show when importing security policy in Security Configuration and Analysis tool
rename c:\Install\sceregvl.inf sceregvl.done


:: Remove SSLv2 weak ciphers for IIS
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v "Enabled" /t REG_DWORD /d "0" /f
REG ADD "HKLM\System\CurrentControlSet\Control\CrashControl" /v "CrashDumpEnabled" /t REG_DWORD /d "2" /f

echo.
echo.
echo Base Build script complete
echo.
echo Next steps:
echo ** Import Security Configuration
echo ** Turn on WinRM
echo ** Configure Windows Firewall
echo ** Install Windows Features
echo ** Run Windows Updates

:: shutdown /r
:: pause
::a:\windows_hardening.cmd
a:\post_deploy.cmd

