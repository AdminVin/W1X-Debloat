<#############################################################################################################################>
#region 1.0 - Script Settings
$ErrorActionPreference = "SilentlyContinue"
### Log - Start
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
#endregion


<#############################################################################################################################>
#region 2.0  - Diagnostics
Write-Host "2.0 Diagnostics" -ForegroundColor Green
# Verbose Status Messaging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value "1"
Write-Host "2.1 Verbose Status Messaging Enabled" -ForegroundColor Green
#endregion


<#############################################################################################################################>
<# Applications #>
Write-Host "3.0 Applications" -ForegroundColor Green

#region Windows 10 - 3.1 Applications - Metro
if((Get-WMIObject win32_operatingsystem) | Where-Object {$_.Name -like "Microsoft Windows 10*"}) 
{
Write-Host "3.1 Applications - Metro" -ForegroundColor Green
# Default Windows Bloatware
Get-AppxPackage -AllUsers "Microsoft.3DBuilder*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.549981C3F5F10*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Appconnector*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingFinance*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingFoodAndDrink*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingHealthAndFitness*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingNews*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingSports*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingTranslator*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingTravel*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.CommsPhone*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ConnectivityStore*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsFeedbackHub*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.GetHelp*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Getstarted*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Messaging*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Microsoft3DViewer*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftOfficeHub*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftPowerBIForWindows*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MixedReality.Portal*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.NetworkSpeedTest*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Office.Sway*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.OneConnect*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.People*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Print3D*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.SkypeApp*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "MicrosoftTeams*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Todos*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Wallet*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Whiteboard*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsMaps*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsPhone*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsReadingList*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.YourPhone*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ZuneMusic*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ZuneVideo*" | Remove-AppxPackage | Out-Null
# Third Party General Bloatware
Get-AppxPackage -AllUsers "*ACGMediaPlayer*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*ActiproSoftwareLLC*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*AdobePhotoshopExpress*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Amazon.com.Amazon*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Asphalt8Airborne*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*AutodeskSketchBook*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*BubbleWitch3Saga*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*CaesarsSlotsFreeCasino*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*CandyCrush*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*COOKINGFEVER*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*CyberLinkMediaSuiteEssentials*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Disney*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*DrawboardPDF*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Duolingo-LearnLanguagesforFree*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*EclipseManager*" | Remove-AppxPackage | Out-Null
#Get-AppxPackage -AllUsers "*Facebook*" | Remove-AppxPackage | Out-Null #FaceBook/Facebook Messenger (Social Media)
Get-AppxPackage -AllUsers "*FarmVille2CountryEscape*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*FitbitCoach*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Flipboard*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*HiddenCity*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Hulu*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*iHeartRadio*" | Remove-AppxPackage | Out-Null
#Get-AppxPackage -AllUsers "*Instagram*" | Remove-AppxPackage | Out-Null # Instagram (Social Media)
Get-AppxPackage -AllUsers "*Keeper*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Kindle*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*LinkedInforWindows*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*MarchofEmpires*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*NYTCrossword*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*OneCalendar*" | Remove-AppxPackage | Out-Null
#Get-AppxPackage -AllUsers "*Pandora*" | Remove-AppxPackage | Out-Null #Pandora (Music)
Get-AppxPackage -AllUsers "*PhototasticCollage*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*PicsArt-PhotoStudio*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*PolarrPhotoEditorAcademicEdition*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Prime*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*RoyalRevolt*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Shazam*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Sidia.LiveWallpaper*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*SlingTV*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Speed" | Remove-AppxPackage | Out-Null
#Get-AppxPackage -AllUsers "*SpotifyAB.SpotifyMusic*" | Remove-AppxPackage | Out-Null #Spotify (Music)
Get-AppxPackage -AllUsers "*Sway*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*TuneInRadio*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Twitter*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Viber*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*WinZipUniversal*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*Wunderlist*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "*XING*" | Remove-AppxPackage | Out-Null
# Samsung Bloatware
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.1412377A9806A*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.NewVoiceNote*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCoLtd.SamsungNotes*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCoLtd.SamsungFlux*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.StudioPlus*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungWelcome*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungUpdate*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungSecurity1.2*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungScreenRecording*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungQuickSearch*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungCloudBluetoothSync*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.PCGallery*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService*" | Remove-AppxPackage | Out-Null
Get-AppxPackage -AllUsers "4AE8B7C2.BOOKING.COMPARTNERAPPSAMSUNGEDITION*" | Remove-AppxPackage | Out-Null
}
else {
#Write-Host "Windows 11 Detected, Skipping."
}
#endregion


#region Windows 11 - 3.1 Applications - Metro
if((Get-WMIObject win32_operatingsystem) | Where-Object {$_.Name -like "Microsoft Windows 11*"}) 
{
Write-Host "3.1 Applications - Metro" -ForegroundColor Green
# Default Windows Bloatware
Get-AppxPackage -AllUsers "Microsoft.3DBuilder*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.549981C3F5F10*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Appconnector*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingFinance*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingFoodAndDrink*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingHealthAndFitness*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingNews*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingSports*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingTranslator*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingTravel*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.CommsPhone*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ConnectivityStore*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsFeedbackHub*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.GetHelp*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Getstarted*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Messaging*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Microsoft3DViewer*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftOfficeHub*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftPowerBIForWindows*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MixedReality.Portal*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.NetworkSpeedTest*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Office.Sway*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.OneConnect*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.People*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Print3D*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.SkypeApp*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "MicrosoftTeams*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Todos*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Wallet*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Whiteboard*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsMaps*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsPhone*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsReadingList*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.YourPhone*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ZuneMusic*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ZuneVideo*" | Remove-AppxPackage -AllUsers | Out-Null
# Third Party General Bloatware
Get-AppxPackage AllUsers "*ACGMediaPlayer*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*ActiproSoftwareLLC*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*AdobePhotoshopExpress*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Amazon.com.Amazon*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Asphalt8Airborne*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*AutodeskSketchBook*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*BubbleWitch3Saga*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*CaesarsSlotsFreeCasino*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*CandyCrush*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*COOKINGFEVER*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*CyberLinkMediaSuiteEssentials*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Disney*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*DrawboardPDF*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Duolingo-LearnLanguagesforFree*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*EclipseManager*" | Remove-AppxPackage -AllUsers | Out-Null
#Get-AppxPackage -AllUsers "*Facebook*" | Remove-AppxPackage -AllUsers | Out-Null #FaceBook/Facebook Messenger (Social Media)
Get-AppxPackage -AllUsers "*FarmVille2CountryEscape*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*FitbitCoach*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Flipboard*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*HiddenCity*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Hulu*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*iHeartRadio*" | Remove-AppxPackage -AllUsers | Out-Null
#Get-AppxPackage -AllUsers "*Instagram*" | Remove-AppxPackage -AllUsers | Out-Null # Instagram (Social Media)
Get-AppxPackage -AllUsers "*Keeper*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Kindle*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*LinkedInforWindows*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*MarchofEmpires*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*NYTCrossword*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*OneCalendar*" | Remove-AppxPackage -AllUsers | Out-Null
#Get-AppxPackage -AllUsers "*Pandora*" | Remove-AppxPackage -AllUsers | Out-Null #Pandora (Music)
Get-AppxPackage -AllUsers "*PhototasticCollage*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*PicsArt-PhotoStudio*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*PolarrPhotoEditorAcademicEdition*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Prime*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*RoyalRevolt*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Shazam*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Sidia.LiveWallpaper*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*SlingTV*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Speed" | Remove-AppxPackage -AllUsers | Out-Null
#Get-AppxPackage -AllUsers "*SpotifyAB.SpotifyMusic*" | Remove-AppxPackage -AllUsers | Out-Null #Spotify (Music)
Get-AppxPackage -AllUsers "*Sway*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*TuneInRadio*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Twitter*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Viber*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*WinZipUniversal*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*Wunderlist*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "*XING*" | Remove-AppxPackage -AllUsers | Out-Null
# Samsung Bloatware
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.1412377A9806A*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.NewVoiceNote*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCoLtd.SamsungNotes*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCoLtd.SamsungFlux*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.StudioPlus*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungWelcome*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungUpdate*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungSecurity1.2*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungScreenRecording*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungQuickSearch*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungCloudBluetoothSync*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.PCGallery*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService*" | Remove-AppxPackage -AllUsers | Out-Null
Get-AppxPackage -AllUsers "4AE8B7C2.BOOKING.COMPARTNERAPPSAMSUNGEDITION*" | Remove-AppxPackage -AllUsers | Out-Null
}
else {
#Write-Host "Windows 10 Detected, Skipping."
}
#endregion

# Disable SILENT installation of NEW third party apps
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Value "0"
# Disable Start Menu metro app suggestions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value "0"
# Disable future installs/re-installs of factory/OEM Metro Apps
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OEMPreInstalledAppsEnabled" -Value "0"


#region Windows 10/11 - Applications - Desktop
Write-Host "3.2 Applications - Desktop" -ForegroundColor Green
# 3.2.1 Edge
Write-Host "3.2.1 Microsoft Edge" -ForegroundColor Green
## Services
Get-Service "edgeupdate" | Stop-Service | Out-Null
Get-Service "edgeupdate" | Set-Service -StartupType Disabled | Out-Null
Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate" -Recurse -Confirm:$false -Force
Get-Service "edgeupdatem" | Stop-Service | Out-Null
Get-Service "edgeupdatem"  | Set-Service -StartupType Disabled | Out-Null
Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem" -Recurse -Confirm:$false -Force
Write-Host "Disabled Microsoft Edge - Auto Update Services" -ForegroundColor Green
## Scheduled Tasks
Get-Scheduledtask "*edge*" | Disable-ScheduledTask | Out-Null
Write-Host "Disabled Microsoft Edge - Auto Start (Scheduled Task)" -ForegroundColor Green
## Auto Start
Set-Location HKLM:
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null}
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value "0" -PropertyType DWord -Force | Out-Null
Set-Location HKCU:
Set-Location "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\"
Remove-ItemProperty -Path. -Name "*MicrosoftEdge*" -Force | Out-Null
Set-Location "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Remove-ItemProperty -Path. -Name "*MicrosoftEdge*" -Force | Out-Null
Set-Location C:/
Write-Host "Disabled Microsoft Edge - Auto Start (Startup Entry)" -ForegroundColor Green
# Tracking
Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'DoNotTrack' -Value '1'
Write-Host "Disabled Microsoft Edge - Tracking" -ForegroundColor Green
# Addon IE to Edge Removal
Get-ChildItem -Path "C:\Program Files (x86)\Microsoft\Edge\Application" -Recurse -Filter "BHO" | Remove-Item -Force -Recurse | Out-Null
Write-Host "Removed Microsoft Edge - Addon - IE to Edge" -ForegroundColor Green

# 3.2.2 OneDrive
Write-Host "3.2.2 Microsoft One Drive" -ForegroundColor Green
## Close OneDrive (if running in background)
taskkill /f /im OneDrive.exe
taskkill /f /im FileCoAuth.exe
## Official Removal
# x86
Start-Process -FilePath "$Env:WinDir\System32\OneDriveSetup.exe" -WorkingDirectory "$Env:WinDir\System32\" -ArgumentList "/uninstall"
# x64
Start-Process -FilePath "$Env:WinDir\SysWOW64\OneDriveSetup.exe" -WorkingDirectory "$Env:WinDir\SysWOW64\" -ArgumentList "/uninstall"
## Files Cleanup
# File Explorer - Navigation Bar
if((Test-Path -LiteralPath "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}") -ne $true) {  New-Item "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force | Out-Null };
New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name '(default)' -Value 'OneDrive' -PropertyType String -Force | Out-Null;
New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value 0 -PropertyType DWord -Force | Out-Null;
# AppData / Local
Remove-Item -Path "$env:localappdata\OneDrive" -Recurse -Confirm:$false -Force
# ProgramData
Remove-Item -Path "$env:programdata\Microsoft OneDrive" -Recurse -Force 
# Shortcuts
Remove-Item -Path "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force
Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force
# Program Files
Remove-Item -LiteralPath "C:\Program Files (x86)\Microsoft OneDrive" -Recurse -Confirm:$false -Force
Remove-Item -LiteralPath "C:\Program Files\Microsoft OneDrive" -Recurse -Confirm:$false -Force
## Scheduled Tasks
Get-ScheduledTask "*OneDrive*" | Unregister-ScheduledTask -Confirm:$false
## Services
$ODUPdaterService = Get-WmiObject -Class Win32_Service -Filter "Name='OneDrive Updater Service'"
$ODUPdaterService.delete() | Out-Null
## Registry
# Remove Previous Accounts/Sync Options
Remove-Item -LiteralPath "HKCU:\Software\Microsoft\OneDrive" -Recurse -Confirm:$false -Force
# Remove previously set One Drive settings
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Recurse -Confirm:$false -Force
# Remove Right Click Menu Context Options
Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\FileSyncHelper" -Recurse -Confirm:$false -Force
# Remove from 'Default' user account
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

## Internet Explorer
if((Get-WMIObject win32_operatingsystem) | Where-Object {$_.Name -like "Microsoft Windows 10*"}) 
{
Write-Host "3.2.3 Internet Explorer" -ForegroundColor Green
# Addon 'Send to One Note'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" -Force | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" -Force | Out-Null
Write-Host "Internet Explorer - Addon - REMOVED 'Send to One Note'" -ForegroundColor Green
# Addon 'OneNote Linked Notes'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" -Force | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" -Force | Out-Null
Write-Host "Internet Explorer - Addon - REMOVED 'OneNote Linked Notes'" -ForegroundColor Green
# Addon 'Lync Click to Call'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" -Force | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" -Force | Out-Null
Write-Host "Internet Explorer - Addon - REMOVED 'Lync Click to Call'" -ForegroundColor Green
# Addon IE to Edge Browser Helper Object
Get-ChildItem -Path "C:\Program Files (x86)\Microsoft\Edge\Application" -Recurse -Filter "BHO" | Remove-Item -Force -Recurse
Write-Host "Internet Explorer - Addon - REMOVED 'IE to Edge'" -ForegroundColor Green
}
else {
Write-Host "Windows 11 Detected, Skipping."
}

## One Note
Write-Host "3.2.4 One Note" -ForegroundColor Green
Remove-Item -LiteralPath "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Send to OneNote.lnk" -Force | Out-Null
Write-Host "OneNote - REMOVED 'Send to OneNote'" -ForegroundColor Green

## Mozilla Firefox
# Scheduled Tasks
Get-ScheduledTask "*Firefox Default*" | Unregister-ScheduledTask -Confirm:$false
Write-Host "Firefox - Disabled 'Periodic requests to set as default browser'" -ForegroundColor Green

## 3.2.6 Teams (Home / Small Business)
Write-Host "3.2.6 Teams (Home / Small Business)" -ForegroundColor Green
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarMn' -Value '0' -PropertyType DWord -Force | Out-Null
Set-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarMn' -Value '0' -Force | Out-Null
Write-Host "Teams (Home / Small Business) - Removed Taskbar Shortcut" -ForegroundColor Green

## 3.2.7 Teams (Work or School)
Write-Host "3.2.7 Teams (Work or School) - Disabled Auto Start" -ForegroundColor Green
Remove-ItemProperty -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "com.squirrel.Teams.Teams" -Force
Remove-ItemProperty -LiteralPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "TeamsMachineInstaller" -Force
Write-Host "Teams (Work or School) - Disabled Auto Start" -ForegroundColor Green
#endregion


<#############################################################################################################################>
# 4.0 - Services and Scheduled Tasks
#region Windows 10 - Services and Scheduled Tasks
if((Get-WMIObject win32_operatingsystem) | Where-Object {$_.Name -like "Microsoft Windows 10*"}) 
{
# Services
Write-Host "4.1 Services" -ForegroundColor Green
Get-Service Diagtrack,Fax,PhoneSvc,WMPNetworkSvc,DmwApPushService,WpcMonSvc | Stop-Service | Set-Service -StartupType Disabled
# Scheduled Tasks
Write-Host "4.2 Scheduled Tasks" -ForegroundColor Green
Get-Scheduledtask "UpdateLibrary" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Proxy" | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "SmartScreenSpecific" | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "Microsoft Compatibility Appraiser" | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "Consolidator" | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "KernelCeipTask" | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "UsbCeip" | Disable-ScheduledTask | Out-Null 
Get-Scheduledtask "Microsoft-Windows-DiskDiagnosticDataCollector" | Disable-ScheduledTask | Out-Null #Required for InTune
Get-Scheduledtask "GatherNetworkInfo" | Disable-ScheduledTask | Out-Null  #Required for InTune
Get-Scheduledtask "QueueReporting" | Disable-ScheduledTask | Out-Null 
}
else {
#Write-Host "Windows 11 Detected, Skipping."
}
#endregion


#region Windows 11 - Services and Scheduled Tasks
if((Get-WMIObject win32_operatingsystem) | Where-Object {$_.Name -like "Microsoft Windows 11*"}) 
{
# Services
Write-Host "4.1 Services" -ForegroundColor Green
# Bing Downloaded Maps Manager
Get-Service "MapsBroker" | Stop-Service | Out-Null
Get-Service "MapsBroker" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Bing Downloaded Maps Manager" -ForegroundColor Green
# Bluetooth (Setting to Manual in the event BT is used.)
Get-Service "BTAGService" | Stop-Service | Out-Null
Get-Service "BTAGService" | Set-Service -StartupType Manual | Out-Null
Get-Service "bthserv" | Stop-Service | Out-Null
Get-Service "bthserv" | Set-Service -StartupType Manual | Out-Null
Write-Host "Set to Manual: Bluetooth" -ForegroundColor Green
# Celluar Time
Get-Service "autotimesvc" | Stop-Service | Out-Null
Get-Service "autotimesvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Celluar Time" -ForegroundColor Green
# Parental Controls
Get-Service "WpcMonSvc" | Stop-Service | Out-Null
Get-Service "WpcMonSvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Parental Controls" -ForegroundColor Green
# Phone Service
Get-Service "PhoneSvc" | Stop-Service | Out-Null
Get-Service "PhoneSvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Phone Service" -ForegroundColor Green
# Portable Device Enumerator Service
Get-Service "WPDBusEnum" | Stop-Service | Out-Null
Get-Service "WPDBusEnum" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Portable Device Enumeration Service" -ForegroundColor Green
# Program Compatibility Assistant Service
Get-Service "PcaSvc" | Stop-Service | Out-Null
Get-Service "PcaSvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Program Compatibility Assistant Service" -ForegroundColor Green
# Remote Registry
Get-Service "RemoteRegistry" | Stop-Service | Out-Null
Get-Service "RemoteRegistry" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Remote Registry (Security Increased)" -ForegroundColor Green
# Retail Demo
Get-Service "RetailDemo" | Stop-Service | Out-Null
Get-Service "RetailDemo" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Retail Demo" -ForegroundColor Green
# Themes
Get-Service "Themes" | Stop-Service | Out-Null
Get-Service "Themes" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Touch Keyboard and Handwritting Panel" -ForegroundColor Green
# Windows Insider Service
Get-Service "wisvc" | Stop-Service | Out-Null
Get-Service "wisvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Insider Service" -ForegroundColor Green
# Windows Mobile Hotspot Service
Get-Service "icssvc" | Stop-Service | Out-Null
Get-Service "icssvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Mobile Hotspot Service" -ForegroundColor Green
# Windows Connected User Experiences and Telemetry #InTune
Get-Service "DiagTrack" | Stop-Service | Out-Null
Get-Service "DiagTrack" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Connected User Experiences and Telemetry" -ForegroundColor Green
# Windows Media Player Network Share
Get-Service "WMPNetworkSvc" | Stop-Service | Out-Null
Get-Service "WMPNetworkSvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Media Player Network Share" -ForegroundColor Green
# Windows Mixed Reality OpenXR Service
Get-Service "MixedRealityOpenXRSvc" | Stop-Service | Out-Null
Get-Service "MixedRealityOpenXRSvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Mixed Reality OpenXR Service" -ForegroundColor Green
# Windows Offline Files
Get-Service "CscService" | Stop-Service | Out-Null
Get-Service "CscService" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Offline Files" -ForegroundColor Green

# Scheduled Tasks
Write-Host "4.2 Scheduled Tasks" -ForegroundColor Green
Get-Scheduledtask "Proxy" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "SmartScreenSpecific" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Microsoft Compatibility Appraiser" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Consolidator" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "KernelCeipTask" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "UsbCeip" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Microsoft-Windows-DiskDiagnosticDataCollector" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "GatherNetworkInfo" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "QueueReporting" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "UpdateLibrary" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Microsoft\Windows\Autochk\Proxy" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Disable-ScheduledTask | Out-Null
}
else {
#Write-Host "Windows 10 Detected, Skipping."
}
#endregion


<#############################################################################################################################>
#region 5.0 - Quality of Life
Write-Host "5.0 Quality of Life" -ForegroundColor Green


<############### Windows 10 Tweaks ###############>
if((Get-WMIObject win32_operatingsystem) | Where-Object {$_.Name -like "Microsoft Windows 10*"}) 
{
    if((Test-Path -LiteralPath "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32") -ne $true) {  New-Item "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null }
    New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' -Name '(default)' -Value '' -PropertyType String  -Force | Out-Null
    Write-Host "Explorer: Restored W10 - Right Click Context Menu (Preference)" -ForegroundColor Green

    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value "0" -Force | Out-Null
Write-Host "Explorer: Disable Ads in File Explorer (Performance)" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" -Name "Enabled" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Value "0" -Force | Out-Null
Write-Host "Cortana - Disabled 'Microsoft from getting to know you' (Privacy)" -ForegroundColor Green

Set-Itemproperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value '0' -Force | Out-Null
Write-Host "Cortana: Disabled 'Activity Feed' in Start Menu (Privacy)" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value "0" -Force | Out-Null
Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value "0" -Force | Out-Null
Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value "0" -Force | Out-Null
Write-Host "Windows: Disabled Lockscreen suggestions and rotating pictures (Preference)" -ForegroundColor Green

Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value "0" -Force | Out-Null
Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value "0" -Force | Out-Null
Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value "1" -Force | Out-Null
Write-Host "Windows: Disabled Feedback Prompts (Privacy)" -ForegroundColor Green

Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value "1" -Force | Out-Null
Write-Host "Windows: Disabled Tips (Performance)" -ForegroundColor Green
}
else {
#Write-Host "Windows 11 Detected, Skipping."
}


<############### Windows 11 Tweaks ###############>
if((Get-WMIObject win32_operatingsystem) | Where-Object {$_.Name -like "Microsoft Windows 11*"}) 
{
if((Test-Path -LiteralPath "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32") -ne $true) {  New-Item "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' -Name '(default)' -Value '' -PropertyType String  -Force | Out-Null
Write-Host "Windows: Restored W10 - Right Click Context Menu (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_Layout' -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "Start Menu/Taskbar: Set Layout to reduce 'Recommened Apps' (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'EnableSnapBar' -Value 0 -PropertyType DWord -Force | Out-Null
Write-Host "Explorer: Disabled 'Snap Layout' Overlay (Preference)" -ForegroundColor Green

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -PropertyType "Dword" -Name "TaskbarAl" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value "0" -Force | Out-Null
Write-Host "Start Menu/Taskbar: Alignment - Left (Preference)" -ForegroundColor Green
}
else {
#Write-Host "Windows 10 Detected, Skipping."
}


<### Windows 10/11 Tweaks ###>
# Take Ownership (Right Click Menu)
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\runas") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\*\shell\runas" -Force | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\runas\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\*\shell\runas\command" -Force | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\runas") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\runas" -Force | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\runas\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\runas\command" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas\command' -Name '(default)' -Value 'cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas\command' -Name 'IsolatedCommand' -Value 'cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\command' -Name '(default)' -Value 'cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\command' -Name 'IsolatedCommand' -Value 'cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\' -Name 'Icon' -Value 'imageres.dll,-5311' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name 'Icon' -Value 'imageres.dll,-5311' -PropertyType String -Force | Out-Null
Write-Host "Windows: Adding File/Folder Take Ownership - Right Click Context Menu (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Priority' -Value 6 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Scheduling Category' -Value 'High' -PropertyType String -Force | Out-Null
Write-Host "Windows: Updating 'MMCSS' to prioritize games with higher system resources (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex' -Value -1 -PropertyType DWord -Force | Out-Null
Write-Host "Network: Disabled Acceleration (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0 -PropertyType DWord -Force | Out-Null
Write-Host "Windows: Disabled Fast Startup - Restored 'Fresh' Reboot (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "Windows: Set paging file to clear at Shutdown (Privacy)" -ForegroundColor Green

# Source: https://www.thewindowsclub.com/disable-windows-10-startup-delay-startupdelayinmsec (Default=10, New Default=0)
if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize' -Name 'StartupDelayInMSec' -Value 0 -PropertyType DWord -Force | Out-Null
Write-Host "Windows: Disabled Startup Delay (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name '(default)' -Value 'Copy &as path' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'InvokeCommandOnSelection' -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'VerbHandler' -Value '{f3d06e7c-1e45-4a26-847e-f9fcdee59be0}' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'VerbName' -Value 'copyaspath' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'Icon' -Value 'imageres.dll,-5302' -PropertyType String -Force | Out-Null
Write-Host "File Explorer: Added 'Copy as Path' - Right Click Context Menu (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\pintohomefile") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\*\shell\pintohomefile" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\pintohomefile' -Name 'ProgrammaticAccessOnly' -Value '' -PropertyType String -Force | Out-Null
Write-Host "File Explorer: Removed 'Add to Favorites' - Right Click Context Menu (Preference)" -ForegroundColor Green

Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'Extended' -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'Icon' -Value 'imageres.dll,-5203' -PropertyType String -Force | Out-Null
Write-Host "File Explorer: Added 'Run as different user' - Right Click Context Menu (Preference)" -ForegroundColor Green

# Sticky Keys
if((Test-Path -LiteralPath "HKCU:\Control Panel\Accessibility\StickyKeys") -ne $true) {  New-Item "HKCU:\Control Panel\Accessibility\StickyKeys" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name 'Flags' -Value '506' -PropertyType String -Force | Out-Null
# Filter Keys
if((Test-Path -LiteralPath "HKCU:\Control Panel\Accessibility\ToggleKeys") -ne $true) {  New-Item "HKCU:\Control Panel\Accessibility\ToggleKeys" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Accessibility\ToggleKeys' -Name 'Flags' -Value '58' -PropertyType String -Force | Out-Null
Write-Host "Windows: Disabled Filter & Sticky Keys (Preference)" -ForegroundColor Green

Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value "1" -Force | Out-Null
Write-Host "Windows: Disabled Troubleshooting 'Steps Recorder' (Performance)" -ForegroundColor Green

# Source: https://www.majorgeeks.com/content/page/irpstacksize.html (Default 15-20 connections, increased to 50)
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'IRPStackSize' -Value 48 -PropertyType DWord -Force | Out-Null
Write-Host "Network: Increased Performance for 'I/O Request Packet Stack Size (Performance)" -ForegroundColor Green

#Source: https://www.elevenforum.com/t/enable-or-disable-store-activity-history-on-device-in-windows-11.7812/ #Note: Potentially needed for InTune
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Value 0 -PropertyType DWord -Force | Out-Null
Write-Host "File Explorer: Disabled Activity Log (Privacy)" -ForegroundColor Green

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name "fDenyTSConnections" -value "0" -Force | Out-Null
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Host "Remote Desktop: Enabled (Preference)" -ForegroundColor Green

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -PropertyType "Dword" -Name "ToastEnabled" -Value "0" | Out-Null
Write-host "Windows: Disabled Toast Notifications (Performance)" -ForegroundColor Green

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -PropertyType "Dword" -Name "ShowTaskViewButton" -Value "0" | Out-Null
Write-host "Start Menu/Taskbar: Removed 'Task View' Button (Preference)" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchBoxTaskbarMode" -Value "0" -Type "DWord" -Force | Out-Null
Write-host "Start Menu/Taskbar: Removed 'Search' Button (Preference)" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value "0" | Out-Null
Write-Host "Explorer: Enabled Display of Known File Extensions (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Force }
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowFrequent' -Value "0" -PropertyType DWord -Force | Out-Null
Write-Host "Explorer: Disabled 'Recent Folders' in Quick Access (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Control Panel\Desktop\WindowMetrics") -ne $true) {  New-Item "HKCU:\Control Panel\Desktop\WindowMetrics" -Force }
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name 'MinAnimate' -Value '0' -PropertyType String -Force | Out-Null
Write-Host "Explorer: Disabled Explorer Animations (Performance)" -ForegroundColor Green

# Add "Open with Powershell (Admin)" to Right Click Context Menu
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin" -Force | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command" -Force | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin" -Force | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command" -Force | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin" -Force | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command" -Force | Out-Null }
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Classes\LibraryFolder\Background\shell\PowerShellAsAdmin" -Force | Out-Null
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'Extended' -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value '' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'Extended' -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value '' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'Extended' -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value '' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLinkedConnections' -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "Explorer: Added 'Open with PowerShell (Admin)' - Right Click Context Menu (Preference)" -ForegroundColor Green

# Disable 'High Precision Event Timer' to prevent input lag/delays
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
Write-Host "Disabled 'High Precision Event Timer' - Formerly Multimedia Timer (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Control Panel\Desktop") -ne $true) {  New-Item "HKCU:\Control Panel\Desktop" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control" -Force | Out-Null }
New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop" -Name 'ForegroundLockTimeout' -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop" -Name 'HungAppTimeout' -Value '400' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop" -Name 'WaitToKillAppTimeout' -Value '500' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'WaitToKillServiceTimeout' -Value '500' -PropertyType String -Force | Out-Null
Write-Host "Windows: Enabled Faster Shutdown (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowDriveLettersFirst' -Value 4 -PropertyType DWord -Force | Out-Null
Write-Host "Explorer: Drive letters PRE drive label [Example: '(C:) Windows vs. Windows (C:)]' (Preference)" -ForegroundColor Green

# Source: http://donewmouseaccel.blogspot.com/
if((Test-Path -LiteralPath "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse") -ne $true) {  New-Item "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse" -Force | Out-Null }
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseSpeed' -Value '0' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold1' -Value '0' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold2' -Value '0' -PropertyType String -Force | Out-Null
if((Test-Path -LiteralPath "HKCU:\Control Panel\Mouse") -ne $true) {  New-Item "HKCU:\Control Panel\Mouse" -Force }
if((Test-Path -LiteralPath "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse") -ne $true) {  New-Item "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value "([byte[]](0x	00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x	C0,0xCC,0x0C,0x00,0x00,0x00,0x00,0x00,0x	80,0x99,0x19,0x00,0x00,0x00,0x00,0x00,0x	40,0x66,0x26,0x00,0x00,0x00,0x00,0x00,0x	00,0x33,0x33,0x00,0x00,0x00,0x00,0x00))" -PropertyType Binary -Force | Out-Null
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value "([byte[]](0x	00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0x70,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0xA8,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0xE0,0x00,0x00,0x00,0x00,0x00))" -PropertyType Binary -Force | Out-Null
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseSpeed' -Value '0' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold1' -Value '0' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold2' -Value '0' -PropertyType String -Force | Out-Null
Write-Host "Mouse: Acceleration Fix (Performance/Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Value 1 -PropertyType DWord -Force | Out-Null
Write-Host "Explorer: Set Explorer to open with 'This PC' instead of 'Most Recent' (Preference)" -ForegroundColor Green

#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "2"
#Write-Host "UAC: Disabled Prompt (Performance)" -ForegroundColor Green

#Set-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value "1" -Force | Out-Null
#Write-Host "Explorer: Disabled 'Recent Files' in Explorer (Performance) [Skipped]" -ForegroundColor Yellow

#Set-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value "1" -Force | Out-Null
#Write-Host "Explorer: Disabled Recent Files/Folders in Start Menu and Explorer (Performance) [Skipped]" -ForegroundColor Yellow
#endregion


<#############################################################################################################################>
#region 6.0 - Performance
Write-Host "6.0 Performance" -ForegroundColor Green
Powercfg /Change monitor-timeout-ac 15
Powercfg /Change monitor-timeout-dc 15
Write-Host "Sleep Settings: Monitor (Battery: 15 Mins | AC: 15 Mins)" -ForegroundColor Green

Powercfg /Change standby-timeout-ac 0
Powercfg /Change standby-timeout-dc 60
Write-Host "Sleep Settings: PC (Battery: 1 Hour | AC: Never)" -ForegroundColor Green

powercfg /Change -disk-timeout-dc 0
powercfg /Change -disk-timeout-ac 0
Write-Host "Sleep Settings: Hard Drive (Battery: Never | AC: Never)" -ForegroundColor Green

powercfg /Change -hibernate-timeout-ac 0
powercfg /Change -hibernate-timeout-dc 0
powercfg -h off
Write-Host "Sleep Settings: Hibernate Disabled" -ForegroundColor Green

powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
Write-Host "Sleep Settings: Changed 'Closing Lid' action to turn off screen" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -force | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowSleepOption' -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowHibernateOption' -Value 0 -PropertyType DWord -Force | Out-Null
Write-Host "Sleep Settings: Disabled Sleep/Hibernate from Start Menu" -ForegroundColor Green

Set-Itemproperty -path "HKCU:\Control Panel\Desktop" -Name 'MenuShowDelay' -value '50'
Write-Host "Start Menu: Animation Time Reduced" -ForegroundColor Green

$ActiveNetworkAdapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name
$ActiveNetworkAdapterConverted = $ActiveNetworkAdapter.Name
Disable-NetAdapterPowerManagement -Name "$ActiveNetworkAdapterConverted" -DeviceSleepOnDisconnect -NoRestart | Out-Null
Write-Host "Network: Disabled Ethernet/Wireless Power Saving Settings" -ForegroundColor Green
#endregion


<#############################################################################################################################>
#region 7.0 - Privacy
Write-Host "7.0 Privacy" -ForegroundColor Green
## Applications
Write-Host "7.1 Applications" -ForegroundColor Green
Write-Host "Applications - Location Permissions" -ForegroundColor Green
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" | Out-Null
Set-Location HKLM:
New-Item -Path ".SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" | Out-Null
New-ItemProperty -Path ".SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value "1"
New-Item -Path ".\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" | Out-Null
New-ItemProperty -Path ".\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "EnableStatus" -Type DWord -Value "1" | Out-Null
Write-Host "Applications - Diagnostics"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" | Out-Null

Write-Host "7.2 Keyboard" -ForegroundColor Green
Write-Host "Keyboard - Improved Inking and Typing Reconition" -ForegroundColor Green
# Disable 'Improve inking and typing recognition'
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowLinguisticDataCollection") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowLinguisticDataCollection" | Out-Null };
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowLinguisticDataCollection" -Name "value" -Value "0" -PropertyType DWord -Force | Out-Null
if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Input\TIPC") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Input\TIPC" -Force | Out-Null };
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Input\TIPC' -Name 'Enabled' -Value 0 -PropertyType DWord -Force | Out-Null

Write-Host "7.3 Clipboard" -ForegroundColor Green
Write-Host "Clipboard - 'Smart Clipboard'" -ForegroundColor Green
if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" -Force | Out-Null };
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard' -Name 'Disabled' -Value 1 -PropertyType DWord -Force | Out-Null

Write-Host "7.4 Telemetry" -ForegroundColor Green #InTune Required
# Disable Tailored Experiences With Diagnostic Data
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -type "Dword" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value "0"
# Disable Telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -Type DWord -Value 0 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0 | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0 | Out-Null
# Firewall Block
Set-NetFirewallProfile -all
netsh advfirewall firewall add rule name="Telementry Block - Inbound" dir=in action=block remoteip=134.170.30.202,137.116.81.24,157.56.106.189,184.86.53.99,2.22.61.43,2.22.61.66,204.79.197.200,23.218.212.69,65.39.117.23,65.55.108.23,64.4.54.254 enable=yes
netsh advfirewall firewall add rule name="Telementry Block - Outbound" dir=out action=block remoteip=65.55.252.43,65.52.108.29,191.232.139.254,65.55.252.92,65.55.252.63,65.55.252.93,65.55.252.43,65.52.108.29,194.44.4.200,194.44.4.208,157.56.91.77,65.52.100.7,65.52.100.91,65.52.100.93,65.52.100.92,65.52.100.94,65.52.100.9,65.52.100.11,168.63.108.233,157.56.74.250,111.221.29.177,64.4.54.32,207.68.166.254,207.46.223.94,65.55.252.71,64.4.54.22,131.107.113.238,23.99.10.11,68.232.34.200,204.79.197.200,157.56.77.139,134.170.58.121,134.170.58.123,134.170.53.29,66.119.144.190,134.170.58.189,134.170.58.118,134.170.53.30,134.170.51.190,157.56.121.89,134.170.115.60,204.79.197.200,104.82.22.249,134.170.185.70,64.4.6.100,65.55.39.10,157.55.129.21,207.46.194.25,23.102.21.4,173.194.113.220,173.194.113.219,216.58.209.166,157.56.91.82,157.56.23.91,104.82.14.146,207.123.56.252,185.13.160.61,8.254.209.254,198.78.208.254,185.13.160.61,185.13.160.61,8.254.209.254,207.123.56.252,68.232.34.200,65.52.100.91,65.52.100.7,207.46.101.29,65.55.108.23,23.218.212.69 enable=yes
#endregion


<#############################################################################################################################>
#region 8.0 - Script Settings
### Log - End
# Log Locally
"Script Duration" | Out-File -Append -FilePath $LogFile
$Timer.Elapsed | Select-Object Hours, Minutes, Seconds | Format-Table | Out-File -Append -FilePath $LogFile
$Timer.Stop()
$TimerFinal = $Timer.Elapsed | Select-Object Hours, Minutes, Seconds | Format-Table
Write-Host "8.0 Log: Script Duration" -ForegroundColor Green
$TimerFinal
Write-Host "Log file located at $LogFile" -ForegroundColor Yellow
#endregion


<#############################################################################################################################>
#region 9.0 - Notify User / Reboot
Write-Host " "
Write-Host " "
Write-Host "***************************************************************" -ForegroundColor Green
Write-Host "*    Windows 10-11 Debloat & Optimization has completed!      *" -ForegroundColor Green
Write-Host "*                                                             *" -ForegroundColor Green
Write-Host "*                                                             *" -ForegroundColor Green
Write-Host "* For all changes to take effect please reboot your computer! *" -ForegroundColor Green
Write-Host "***************************************************************" -ForegroundColor Green
#endregion