#Run SDELETE on the C drive
cmd /c Dism /online /cleanup-image /startcomponentcleanup 
cmd /c %SystemRoot%\System32\reg.exe ADD HKCU\Software\Sysinternals\SDelete /v EulaAccepted /t REG_DWORD /d 1 /f
cmd /c A:\sdelete.exe -q -z C:
