$TotalRamInstalled = (systeminfo | Select-String 'Total Physical Memory:').ToString().Split(':')[1].Trim()
$TotalRamInstalled = $TotalRamInstalled.Substring(0,2)
if (($TotalRamInstalled -ge "32")) {
    Write-Host "Disabling Page File"
    $pagefileset = Get-WmiObject win32_pagefilesetting | Where-Object {$_.caption -like 'C:*'}
    $pagefileset.Delete()
    $pagefileset = wmi win32_pagefilesetting | Where-Object {$_.caption -like 'D:*'}
    $pagefileset.Delete()
    $pagefileset = wmi win32_pagefilesetting | Where-Object {$_.caption -like 'E:*'}
    $pagefileset.Delete() | Out-Null
}
else {
    Write-Host "Setting page file to clear on shutdown"
}