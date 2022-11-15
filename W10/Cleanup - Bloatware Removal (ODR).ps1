<### Elevating Powershell Script with Administrative Rights ###>
<# Write-Host "Elevating Powershell Script with Administrative Rights" -ForegroundColor Green
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) { Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs; exit }
#>

<### Log - Start ###>
$PCName = (Get-CIMInstance CIM_ComputerSystem).Name
$Date = Get-Date
$LogFile = "C:\ProgramData\AV\Cleanup\$PCName.txt"
# Check if log directory exists
if (Test-Path -Path "C:\ProgramData\AV\Cleanup") {
    Write-Host "Log folder exists, and does not need to be created." -ForegroundColor Green
} else {
    Write-Host "Log folder does NOT exist, and will be created." -ForegroundColor Red
    New-Item "C:\ProgramData\AV\Cleanup" -Type Directory | Out-Null
	New-Item "C:\ProgramData\AV\Cleanup\$PCName.txt" | Out-Null
}
# Log Locally
$Date | Out-File -Append -FilePath $LogFile
Write-Host "1.0 Log: Script started at $Date" -ForegroundColor Green
$Timer = [System.Diagnostics.Stopwatch]::StartNew()


<### Diagnostics ###>
Write-Host "2.0 Diagnostics" -ForegroundColor Green
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value "1"
Write-Host "2.1 Enabled Verbose Status Messaging" -ForegroundColor Green


<### Applications ###>
Write-Host "3.0 Applications" -ForegroundColor Green
Write-Host "3.1 Applications - Metro" -ForegroundColor Green
# Default Windows Bloatware
Get-AppxPackage -AllUsers "Microsoft.3DBuilder*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.549981C3F5F10*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Appconnector*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingFinance*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingFoodAndDrink*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingHealthAndFitness*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingNews*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingSports*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingTranslator*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingTravel*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.CommsPhone*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ConnectivityStore*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsFeedbackHub*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.GetHelp*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Getstarted*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Messaging*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Microsoft3DViewer*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftOfficeHub*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftPowerBIForWindows*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MixedReality.Portal*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.NetworkSpeedTest*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Office.Sway*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.OneConnect*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.People*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Print3D*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.SkypeApp*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
# Remove "Chat" icon from Taskbar for free edition of "Teams"
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /f /v TaskbarMn /t REG_DWORD /d 0
Get-AppxPackage -AllUsers "MicrosoftTeams*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Todos*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Wallet*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Whiteboard*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsMaps*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsPhone*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsReadingList*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.YourPhone*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ZuneMusic*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ZuneVideo*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
# Third Party General Bloatware
Get-AppxPackage -AllUsers "*ACGMediaPlayer*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*ActiproSoftwareLLC*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*AdobePhotoshopExpress*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Amazon.com.Amazon*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Asphalt8Airborne*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*AutodeskSketchBook*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*BubbleWitch3Saga*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*CaesarsSlotsFreeCasino*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*CandyCrush*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*COOKINGFEVER*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*CyberLinkMediaSuiteEssentials*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Disney*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*DrawboardPDF*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Duolingo-LearnLanguagesforFree*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*EclipseManager*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Facebook*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*FarmVille2CountryEscape*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*FitbitCoach*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Flipboard*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*HiddenCity*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Hulu*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*iHeartRadio*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Instagram*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Keeper*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Kindle*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*LinkedInforWindows*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*MarchofEmpires*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*NYTCrossword*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*OneCalendar*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*PandoraMediaInc*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*PhototasticCollage*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*PicsArt-PhotoStudio*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*PolarrPhotoEditorAcademicEdition*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Prime*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*RoyalRevolt*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Shazam*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Sidia.LiveWallpaper*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*SlingTV*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Speed" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
#Get-AppxPackage -AllUsers "*SpotifyAB.SpotifyMusic*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null # W11 Branded Spotify
Get-AppxPackage -AllUsers "*Sway*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*TuneInRadio*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Twitter*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Viber*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*WinZipUniversal*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Wunderlist*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*XING*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
# Samsung Bloatware
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.1412377A9806A*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.NewVoiceNote*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCoLtd.SamsungNotes*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCoLtd.SamsungFlux*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.StudioPlus*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungWelcome*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungUpdate*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungSecurity1.2*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungScreenRecording*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungQuickSearch*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungCloudBluetoothSync*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.PCGallery*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "4AE8B7C2.BOOKING.COMPARTNERAPPSAMSUNGEDITION*" | Where-Object {$_.InstallLocation -notlike $null} | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null

# Disable SILENT installs of new Apps
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Value "0"
# Start Menu Application suggestions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value "0"
# Disable future installs/re-installs of factory/OEM Metro Apps
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OEMPreInstalledAppsEnabled" -Value "0"

Write-Host "3.2 Applications - Desktop"
# 3.2.1 Edge
Write-Host "3.2.1 Microsoft Edge" -ForegroundColor Green
## Services
Get-Service "edgeupdate" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "edgeupdate" | Set-Service -StartupType Disabled | Out-Null
Get-Service "edgeupdatem" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "edgeupdatem" | Set-Service -StartupType Disabled | Out-Null
Write-Host "3.2.1.1 Disabled Microsoft Edge - Auto Update Services" -ForegroundColor Green
## Scheduled Tasks
Get-Scheduledtask "*edge*" -erroraction silentlycontinue | Disable-ScheduledTask | Out-Null
Write-Host "3.2.1.2 Disabled Microsoft Edge - Auto Start (Scheduled Task)" -ForegroundColor Green
## Auto Start
Set-Location HKLM:
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft" -Force -ErrorAction SilentlyContinue | Out-Null};
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge" -Force -ErrorAction SilentlyContinue | Out-Null};
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force -ErrorAction SilentlyContinue | Out-Null};
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value "0" -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Set-Location HKCU:
Set-Location "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\"
Remove-ItemProperty -Path. -Name "*MicrosoftEdge*" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Location "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Remove-ItemProperty -Path. -Name "*MicrosoftEdge*" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Location C:/
Write-Host "3.2.1.3 Disabled Microsoft Edge - Auto Start (Startup Entry)" -ForegroundColor Green
# Tracking
Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'DoNotTrack' -Value '1'
Write-Host "3.2.1.4 Disabled Microsoft Edge - Tracking" -ForegroundColor Green
# Addon IE to Edge Removal
Get-ChildItem -Path "C:\Program Files (x86)\Microsoft\Edge\Application" -Recurse -Filter "BHO" | Remove-Item -Force -Recurse | Out-Null
Write-Host "3.2.1.5 Removed Microsoft Edge - Addon - IE to Edge" -ForegroundColor Green

# 3.2.2 OneDrive
# Close OneDrive (if running in background)
taskkill /f /im OneDrive.exe
# File Explorer - Remove
if((Test-Path -LiteralPath "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}") -ne $true) {  New-Item "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name '(default)' -Value 'OneDrive' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
# File Sync - Disable		
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Value '1' -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
Set-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value "1" -ErrorAction SilentlyContinue | Out-Null;
# Removal - x86
%SystemRoot%\System32\OneDriveSetup.exe /uninstall
# Removal - x64
%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
# Misc - Leftovers
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "C:\OneDriveTemp"
# Misc - Prevent New User Accounts installing OneDrive
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"
# Shorcut - Start Menu Removal
Remove-Item "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -ErrorAction SilentlyContinue
# Program Files - Cleanup
Remove-Item -LiteralPath "C:\Program Files (x86)\Microsoft OneDrive" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue | Out-Null
# Scheduled Tasks
Get-ScheduledTask "*OneDrive*" | Unregister-ScheduledTask -Confirm:$false
# Services
$ODUPdaterService = Get-WmiObject -Class Win32_Service -Filter "Name='OneDrive Updater Service'"
$ODUPdaterService.delete() | Out-Null
Write-Host "3.2.2 OneDrive Removed" -ForegroundColor Green

## Internet Explorer
# Addon 'Send to One Note'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "3.2.3.1 Internet Explorer - Addon - REMOVED 'Send to One Note'" -ForegroundColor Green
# Addon 'OneNote Linked Notes'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "3.2.3.2 Internet Explorer - Addon - REMOVED 'OneNote Linked Notes'" -ForegroundColor Green
# Addon 'Lync Click to Call'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "3.2.3.3 Internet Explorer - Addon - REMOVED 'Lync Click to Call'" -ForegroundColor Green
# Addon IE to Edge Browser Helper Object
Get-ChildItem -Path "C:\Program Files (x86)\Microsoft\Edge\Application" -Recurse -Filter "BHO" | Remove-Item -Force -Recurse
Write-Host "3.2.3.4 Internet Explorer - Addon - REMOVED 'IE to Edge'" -ForegroundColor Green

## One Note
Write-Host "3.2.4 One Note" -ForegroundColor Green
Remove-Item -LiteralPath "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Send to OneNote.lnk" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "3.2.4.1 OneNote - REMOVED 'Send to OneNote'" -ForegroundColor Green

## Mozilla Firefox
# Scheduled Tasks
Get-ScheduledTask "*Firefox Default*" | Unregister-ScheduledTask -Confirm:$false
Write-Host "3.2.5.1 Firefox - Disabled 'Periodic requests to set as default browser'" -ForegroundColor Green


<### Services and Scheduled Tasks ###>
Write-Host "4.0 Services and Scheduled Tasks" -ForegroundColor Green
# Services
Write-Host "4.1 Services" -ForegroundColor Green
Get-Service Diagtrack,Fax,PhoneSvc,WMPNetworkSvc,DmwApPushService,WpcMonSvc -ErrorAction SilentlyContinue | Stop-Service | Set-Service -StartupType Disabled
# Scheduled Tasks
Write-Host "4.2 Scheduled Tasks" -ForegroundColor Green
Get-Scheduledtask "UpdateLibrary" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Proxy" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "SmartScreenSpecific" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "Microsoft Compatibility Appraiser" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "Consolidator" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "KernelCeipTask" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "UsbCeip" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "Microsoft-Windows-DiskDiagnosticDataCollector" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null #Required for InTune
Get-Scheduledtask "GatherNetworkInfo" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null  #Required for InTune
Get-Scheduledtask "QueueReporting" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null 


<### 5.0 Quality of Life###>
Write-Host "5.0 Quality of Life" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "5.1 Explorer: Disable Ads in File Explorer (Performance)" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" -Name "Enabled" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "5.2 Cortana - Disabled 'Microsoft from getting to know you' (Privacy)" -ForegroundColor Green

Set-Itemproperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value '0' -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "5.3 Cortana: Disabled 'Activity Feed' in Start Menu (Privacy)" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "5.4 Windows: Disabled Lockscreen suggestions and rotating pictures (Preference)" -ForegroundColor Green

Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "5.5 Windows: Disabled Feedback Prompts (Privacy)" -ForegroundColor Green

Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "5.6 Windows: Disabled Troubleshooting 'Steps Recorder' (Performance)" -ForegroundColor Green

Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "5.7 Windows: Disabled Tips (Performance)" -ForegroundColor Green

Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Value "0" #Required by InTune	
Write-Host "5.8 Windows: Disabled Application Telemetry" -ForegroundColor Yellow 

Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Value "1" #Required by InTune
Write-Host "5.8 Windows: Disabled Inventory Collector" -ForegroundColor Yellow 

Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "5.9 Windows: Disabled Consumer Experiences (Performance)" -ForegroundColor Green

Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "EnableConfigFlighting" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "5.10 Windows: Disabled Pre-Release Features (Preference)" -ForegroundColor Green

New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name 'PeopleBand' -PropertyType Dword -Value '0' -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People' -Name 'PeopleBand' -Value '0' -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "5.11 Start: Disabled 'People' in system tray (Preference)" -ForegroundColor Green

Set-ItemProperty -LiteralPath 'HKCU:\Software\Policies\Microsoft\Windows\Explorer' -Name 'DisableNotificationCenter' -Value '0' -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "5.12 Start: Disabled 'Windows Action Center' in system tray (Preference)" -ForegroundColor Green

Set-Itemproperty -path 'HKCU:\Control Panel\Desktop' -Name 'MenuShowDelay' -Value '50'
Write-Host "5.13 Start: Decreased Menu Animation Time (Performance)" -ForegroundColor Green

Remove-Item -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force -ErrorAction SilentlyContinue | Out-Null;
Remove-Item -LiteralPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.14 Windows: Removed '3D Objects' from File Explorer (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Force -ErrorAction SilentlyContinue };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowDriveLettersFirst' -Value 4 -PropertyType DWord -Force -ErrorAction SilentlyContinue;
Write-Host "5.15 File Explorer: Drive letters PRE drive label [Example: '(C:) Windows vs. Windows (C:)]' (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\runas") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\*\shell\runas" -Force -ErrorAction SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\runas\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\*\shell\runas\command" -Force -ErrorAction SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\runas") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\runas" -Force -ErrorAction SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\runas\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\runas\command" -Force -ErrorAction SilentlyContinue };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas\command' -Name '(default)' -Value 'cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas\command' -Name 'IsolatedCommand' -Value 'cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\command' -Name '(default)' -Value 'cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\command' -Name 'IsolatedCommand' -Value 'cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\' -Name 'Icon' -Value 'imageres.dll,-5311' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name 'Icon' -Value 'imageres.dll,-5311' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.16 Windows: Adding File/Folder Take Ownership - Right Click Context Menu (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Control Panel\Desktop") -ne $true) {  New-Item "HKCU:\Control Panel\Desktop" -Force -ErrorAction SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control" -Force -ErrorAction SilentlyContinue };
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'ForegroundLockTimeout' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'HungAppTimeout' -Value '400' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'WaitToKillAppTimeout' -Value '500' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'WaitToKillServiceTimeout' -Value '500' -PropertyType String -Force -ErrorAction SilentlyContinue;
Write-Host "5.17 Windows: Enabled Faster Shutdown (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin" -Force -ErrorAction SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command" -Force -ErrorAction SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin" -Force -ErrorAction SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command" -Force -ErrorAction SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin" -Force -ErrorAction SilentlyContinue };
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command" -Force -ErrorAction SilentlyContinue };
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Classes\LibraryFolder\Background\shell\PowerShellAsAdmin" -Force;
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force -ErrorAction SilentlyContinue };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force -ErrorAction SilentlyContinue;
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'Extended' -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force -ErrorAction SilentlyContinue;
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'Extended' -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force -ErrorAction SilentlyContinue;
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'Extended' -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLinkedConnections' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue;
Write-Host "5.18 File Explorer: Added 'Open with PowerShell (Admin)' -Right Click Context Menu (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.19 Explorer: Launch with 'This PC' instead of 'Most Recent' (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Force  -Force -ErrorAction SilentlyContinue };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowSleepOption' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowHibernateOption' -Value 0 -PropertyType DWord -Force  -Force -ErrorAction SilentlyContinue;
Write-Host "5.20 Start Menu: Remove Sleep/Hibernate from Shutdown Options (Performance)" -ForegroundColor Green

# Source: https://www.majorgeeks.com/content/page/irpstacksize.html 
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'IRPStackSize' -Value 48 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.21 Network: Increase Performance for 'I/O Request Packet Stack Size - Default 15-20 connections, increased to 30 (Performance)" -ForegroundColor Green

#Source: https://www.elevenforum.com/t/enable-or-disable-store-activity-history-on-device-in-windows-11.7812/ #Note: Potentially needed for InTune
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.22 File Explorer: Disable Activity Log (Privacy)" -ForegroundColor Green

# Disable 'High Precision Event Timer' to prevent input lag/delays.
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
Write-Host "5.23 Disabled 'High Precision Event Timer' - Formerly Multimedia Timer (Performance)" -ForegroundColor Green

# Source: http://donewmouseaccel.blogspot.com/
if((Test-Path -LiteralPath "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse") -ne $true) {  New-Item "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseSpeed' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold1' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold2' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
if((Test-Path -LiteralPath "HKCU:\Control Panel\Mouse") -ne $true) {  New-Item "HKCU:\Control Panel\Mouse" -Force -ErrorAction SilentlyContinue };
if((Test-Path -LiteralPath "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse") -ne $true) {  New-Item "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse" -Force -ErrorAction SilentlyContinue | Out-Null};
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value "([byte[]](0x	00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x	C0,0xCC,0x0C,0x00,0x00,0x00,0x00,0x00,0x	80,0x99,0x19,0x00,0x00,0x00,0x00,0x00,0x	40,0x66,0x26,0x00,0x00,0x00,0x00,0x00,0x	00,0x33,0x33,0x00,0x00,0x00,0x00,0x00))" -PropertyType Binary -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value "([byte[]](0x	00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0x70,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0xA8,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0xE0,0x00,0x00,0x00,0x00,0x00))" -PropertyType Binary -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseSpeed' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold1' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold2' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.24 Mouse: MarkC's Acceleration Fix (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.25 Windows: Disabled Fast Startup - Restored 'Fresh' Reboot (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Priority' -Value 6 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Scheduling Category' -Value 'High' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.26 Windows: Updating 'MMCSS' - Prioritize games with higher system resources (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex' -Value -1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.27 Network: Disabled Acceleration (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.28 Windows: Clear Page File at Shutdown (Privacy)" -ForegroundColor Green

# Source: https://www.thewindowsclub.com/disable-windows-10-startup-delay-startupdelayinmsec (Default=10, New Default=0)
if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize' -Name 'StartupDelayInMSec' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.29 Windows: Disable Startup Delay (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name '(default)' -Value 'Copy &as path' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'Icon' -Value 'imageres.dll,-5302' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'InvokeCommandOnSelection' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'VerbHandler' -Value '{f3d06e7c-1e45-4a26-847e-f9fcdee59be0}' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'VerbName' -Value 'copyaspath' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
<# Reference for Windows Defaults
## Remove Default 'Copy As Path'
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\CopyAsPathMenu" -Force -ErrorAction SilentlyContinue | Out-Null
## Restore Default 'Copy As Path'
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\CopyAsPathMenu") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\CopyAsPathMenu" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers\CopyAsPathMenu' -Name '(default)' -Value '{f3d06e7c-1e45-4a26-847e-f9fcdee59be0}' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null; #>
Write-Host "5.30 File Explorer: Added 'Copy as Path' - Right Click Context Menu (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\pintohomefile") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\*\shell\pintohomefile" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\pintohomefile' -Name 'ProgrammaticAccessOnly' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.31 File Explorer: Removed 'Add to Favorites' - Right Click Context Menu (Preference)" -ForegroundColor Green

Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'Extended' -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'Icon' -Value 'imageres.dll,-5203' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "5.32 File Explorer: Added 'Run as different user' - Right Click Context Menu (Preference)" -ForegroundColor Green


<### 6.0 Performance ###>
Write-Host "6.0 Performance" -ForegroundColor Green
Powercfg /Change monitor-timeout-ac 15
Powercfg /Change monitor-timeout-dc 15
Write-Host "6.1 Sleep Settings: Monitor" -ForegroundColor Green

Powercfg /Change standby-timeout-ac 0
Powercfg /Change standby-timeout-dc 60
Write-Host "6.2 Sleep Settings: PC" -ForegroundColor Green

powercfg /Change -disk-timeout-dc 0
powercfg /Change -disk-timeout-ac 0
Write-Host "6.3 Sleep Settings: Hard Drive" -ForegroundColor Green

powercfg /Change -hibernate-timeout-ac 0
powercfg /Change -hibernate-timeout-dc 0
powercfg -h off
Write-Host "6.4 Sleep Settings: Hibernate Disabled" -ForegroundColor Green

powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
Write-Host "6.5 Sleep Settings: Changed 'Closing Lid' action to turn off screen" -ForegroundColor Green

powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 4
powercfg -setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 4
Write-Host "6.6 Sleep Settings: Changed 'Sleep Button' turns off display" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowSleepOption' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowHibernateOption' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
Write-Host "6.7 Sleep Settings: Disabled Sleep/Hibernate from Start Menu" -ForegroundColor Green

Set-Itemproperty -path "HKCU:\Control Panel\Desktop" -Name 'MenuShowDelay' -value '50'
Write-Host "6.8 Start Menu: Animation Time Reduced" -ForegroundColor Green

$ActiveNetworkAdapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name
$ActiveNetworkAdapterConverted = $ActiveNetworkAdapter.Name
Disable-NetAdapterPowerManagement -Name "$ActiveNetworkAdapterConverted" -DeviceSleepOnDisconnect -NoRestart -ErrorAction SilentlyContinue
Write-Host "6.9 Network: Disabled Ethernet/Wireless Power Saving Settings" -ForegroundColor Green


<### Log - End ###>
"Script Duration" | Out-File -Append -FilePath $LogFile
$Timer.Elapsed | Select-Object Hours, Minutes, Seconds | Format-Table | Out-File -Append -FilePath $LogFile
$Timer.Stop()
$TimerFinal = $Timer.Elapsed | Select-Object Hours, Minutes, Seconds | Format-Table
Write-Host "8.0 Log: Script Duration: $TimerFinal" -ForegroundColor Green
Write-Host "Log file located at $LogFile" -ForegroundColor Yellow