REM  QBFC Project Options Begin
REM  REM  HasVersionInfo: No
REM  REM  Companyname: 
REM  REM  Productname: 
REM  REM  Filedescription: 
REM  REM  Copyrights: 
REM  REM  Trademarks: 
REM  REM  Originalname: 
REM  REM  Comments: 
REM  REM  Productversion:  0. 0. 0. 0
REM  REM  Fileversion:  0. 0. 0. 0
REM  REM  Internalname: 
REM  REM  Appicon: 
REM  REM  QBFC Project Options End

@ECHO OFF

:: *** Post-build script for Carlson Wagonlit Travel (Windows Server 2016) ***

:: Reconfigure Pagefile
wmic computersystem set AutomaticManagedPagefile=True

fsutil behavior set disablelastaccess 1

:: Disable Hibernation
powercfg.exe -h off

:: Install VMware tools from mounted ISO 
e:\setup64 /s /v "/qb REBOOT=R"

::set static IP
netsh interface ip set address name="Ethernet0" static 10.213.4.198 255.255.255.0 10.213.4.250
netsh dnsclient set dnsservers name="Ethernet0" source=static address=10.213.252.25 validate=no

::set windows firewall
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy allowinboound,allowoutbound

:: Set Disk TimeOutValue to 190 seconds
reg add "HKLM\SYSTEM\CurrentControlSet\services\Disk" /v "TimeOutValue" /t REG_DWORD /d "190" /f

:: Set TimeZoneKeyName to Pacific just to fix the gui
:: reg add "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v "TimeZoneKeyName" /t REG_SZ /d "Pacific Standard Time" /f

:: ** Create D: Partition **
:: Create c:\diskpart.txt script file.
:: ECHO select volume d > c:\diskpart.txt
:: ECHO assign letter e >> c:\diskpart.txt
:: ECHO select disk 1 >> c:\diskpart.txt
:: ECHO attributes disk clear readonly >> c:\diskpart.txt
:: ECHO online disk >> c:\diskpart.txt
:: ECHO clean >> c:\diskpart.txt
:: ECHO create partition primary align=128 >> c:\diskpart.txt
:: ECHO assign letter d >> c:\diskpart.txt
:: Execute diskpart script.  WARNING:This will destroy everything on disk 1
:: start /wait Diskpart /s c:\diskpart.txt
:: Format D: with NTFS
:: start /wait format d: /FS:NTFS /v:DATA /q /y
:: Delete diskpart.txt
:: DEL C:\diskpart.txt /F /Q


:: Create D: Drive Structure
if not exist D:\Resource md D:\Resource
if not exist D:\Resource\Apps md D:\Resource\Apps
if not exist D:\Resource\Archive md D:\Resource\Archive
if not exist D:\Resource\Data md D:\Resource\Data
if not exist D:\Resource\Development md D:\Resource\Development
if not exist D:\Resource\QA md D:\Resource\QA
if not exist D:\Resource\Staging md D:\Resource\Staging


:::: Add default IIS7 folders
MKDIR D:\Resource\www\dev
MKDIR D:\Resource\www\qa
MKDIR D:\Resource\www\staging
MKDIR D:\Resource\www\prod

:: Set boot delay to 10 seconds (again)
bcdedit /timeout 10

:: Restrict access to Security Log
:: wevtutil sl security /ca:O:SYG:SYD:(A;;0xf0005;;;SY)

:: Add local administrator to "Event Log Readers" group
:: net localgroup "Event Log Readers" administrator /add

:: Rename Administrator
wmic UserAccount where Name="Administrator" call Rename Name="ugxg042"
net user ugxg042 (h@ng3,M3!

:: Rename Guest
wmic UserAccount where Name="Guest" call Rename Name="ugxg052"
net user ugxg052 P4s5W0rd!

:: Temp Account. Commands added to the template, prebuild.
:: net user ugxg062 Global5t@nd@rd /ADD
:: net localgroup administrators ugxg062 /add
:: schtasks /create /sc weekly /d sat /tn "TempUserCleanup" /tr "TempUserCleanup.cmd" /st 12:00
:: net user ugxg062 /del
:: schtasks /delete /tn "TempUserCleanup"

:: Add security warning text and title
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "LegalNoticeText" /t REG_SZ /d "=========================================================== This company-supplied technology you are about to use is owned by Carlson, or one of its family of businesses and has been provided for business purposes. Incidental, personal use of company-supplied technologies is permitted as long as such use does not adversely impact the employee’s work or general business operations. You should never use these technologies in a way that would be construed as inappropriate, unlawful, or unprofessional. Users of company-supplied technologies should have no expectations of privacy. Unless restricted or limited by law, your usage of company-supplied technologies may be monitored without notice. Unless restricted or limited by law, all data residing on this company-supplied technology is the property of the company and is subject to the company’s review whenever the company deems it necessary. Unauthorized changes to company-supplied technologies are prohibited. By using this company-supplied technology, you consent to all of the above. ===========================================================" /f

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "LegalNoticeCaption" /t REG_SZ /d "Carlson Wagonlit Travel" /f
:: Error Denied, added to template. 
:: reg add "HKLM\Software\Microsoft\Windows\HTML Help\CT2016D" /v "CWErevision" /t REG_SZ /d "03142017" /f

::run powershell scripts
::powershell a:\win-updates.ps1
::powershell a:\Win2016features.ps1

::start WinRM
net start winrm

::config WinRM
powershell a:\winrm.ps1

::run windows updates
::powershell a:\win-updates.ps1

::change drive letter
powershell a:\changeCDdrive.ps1

:: Restart the Server
::shutdown /s /t 60 

::ping -n 30 127.0.0.1>nul

::Clean up
RD /S /Q C:\Install
MD C:\Install\Log
:: Delete moved to Post_Deploy.cmd, cannot remove exe while in use.
:: DEL c:\Windows\Post_Deploy.exe /F /Q

ECHO ON
