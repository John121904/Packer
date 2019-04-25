#Change CD drive letter
$drv = Get-WmiObject win32_volume -filter 'DriveLetter = "D:"'
$drv.DriveLetter = "F:"
$drv.Put() | out-null
