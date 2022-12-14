<#############################################################################################################################>
#region 1.0 Log - Start
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
#region 2.0 Diagnostics
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
Get-AppxPackage -AllUsers "Microsoft.3DBuilder*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.549981C3F5F10*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Appconnector*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingFinance*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingFoodAndDrink*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingHealthAndFitness*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingNews*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingSports*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingTranslator*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingTravel*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.CommsPhone*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ConnectivityStore*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsFeedbackHub*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.GetHelp*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Getstarted*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Messaging*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Microsoft3DViewer*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftOfficeHub*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftPowerBIForWindows*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MixedReality.Portal*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.NetworkSpeedTest*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Office.Sway*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.OneConnect*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.People*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Print3D*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.SkypeApp*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "MicrosoftTeams*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Todos*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Wallet*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Whiteboard*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsMaps*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsPhone*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsReadingList*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.YourPhone*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ZuneMusic*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ZuneVideo*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
# Third Party General Bloatware
Get-AppxPackage -AllUsers "*ACGMediaPlayer*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*ActiproSoftwareLLC*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*AdobePhotoshopExpress*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Amazon.com.Amazon*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Asphalt8Airborne*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*AutodeskSketchBook*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*BubbleWitch3Saga*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*CaesarsSlotsFreeCasino*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*CandyCrush*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*COOKINGFEVER*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*CyberLinkMediaSuiteEssentials*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Disney*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*DrawboardPDF*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Duolingo-LearnLanguagesforFree*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*EclipseManager*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
#Get-AppxPackage -AllUsers "*Facebook*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null #FaceBook/Facebook Messenger (Social Media)
Get-AppxPackage -AllUsers "*FarmVille2CountryEscape*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*FitbitCoach*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Flipboard*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*HiddenCity*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Hulu*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*iHeartRadio*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
#Get-AppxPackage -AllUsers "*Instagram*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null # Instagram (Social Media)
Get-AppxPackage -AllUsers "*Keeper*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Kindle*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*LinkedInforWindows*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*MarchofEmpires*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*NYTCrossword*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*OneCalendar*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
#Get-AppxPackage -AllUsers "*Pandora*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null #Pandora (Music)
Get-AppxPackage -AllUsers "*PhototasticCollage*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*PicsArt-PhotoStudio*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*PolarrPhotoEditorAcademicEdition*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Prime*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*RoyalRevolt*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Shazam*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Sidia.LiveWallpaper*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*SlingTV*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Speed" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
#Get-AppxPackage -AllUsers "*SpotifyAB.SpotifyMusic*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null #Spotify (Music)
Get-AppxPackage -AllUsers "*Sway*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*TuneInRadio*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Twitter*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Viber*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*WinZipUniversal*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Wunderlist*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*XING*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
# Samsung Bloatware
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.1412377A9806A*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.NewVoiceNote*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCoLtd.SamsungNotes*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCoLtd.SamsungFlux*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.StudioPlus*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungWelcome*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungUpdate*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungSecurity1.2*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungScreenRecording*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungQuickSearch*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungCloudBluetoothSync*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.PCGallery*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "4AE8B7C2.BOOKING.COMPARTNERAPPSAMSUNGEDITION*" | Remove-AppxPackage -ErrorAction SilentlyContinue | Out-Null
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
Get-AppxPackage -AllUsers "Microsoft.3DBuilder*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.549981C3F5F10*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Appconnector*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingFinance*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingFoodAndDrink*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingHealthAndFitness*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingNews*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingSports*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingTranslator*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.BingTravel*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.CommsPhone*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ConnectivityStore*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsFeedbackHub*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.GetHelp*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Getstarted*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Messaging*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Microsoft3DViewer*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftOfficeHub*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftPowerBIForWindows*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MixedReality.Portal*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.NetworkSpeedTest*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Office.Sway*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.OneConnect*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.People*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Print3D*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.SkypeApp*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "MicrosoftTeams*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Todos*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Wallet*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.Whiteboard*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsMaps*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsPhone*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.WindowsReadingList*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.YourPhone*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ZuneMusic*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "Microsoft.ZuneVideo*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
# Third Party General Bloatware
Get-AppxPackage AllUsers "*ACGMediaPlayer*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*ActiproSoftwareLLC*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*AdobePhotoshopExpress*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Amazon.com.Amazon*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Asphalt8Airborne*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*AutodeskSketchBook*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*BubbleWitch3Saga*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*CaesarsSlotsFreeCasino*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*CandyCrush*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*COOKINGFEVER*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*CyberLinkMediaSuiteEssentials*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Disney*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*DrawboardPDF*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Duolingo-LearnLanguagesforFree*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*EclipseManager*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
#Get-AppxPackage -AllUsers "*Facebook*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null #FaceBook/Facebook Messenger (Social Media)
Get-AppxPackage -AllUsers "*FarmVille2CountryEscape*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*FitbitCoach*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Flipboard*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*HiddenCity*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Hulu*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*iHeartRadio*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
#Get-AppxPackage -AllUsers "*Instagram*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null # Instagram (Social Media)
Get-AppxPackage -AllUsers "*Keeper*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Kindle*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*LinkedInforWindows*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*MarchofEmpires*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*NYTCrossword*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*OneCalendar*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
#Get-AppxPackage -AllUsers "*Pandora*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null #Pandora (Music)
Get-AppxPackage -AllUsers "*PhototasticCollage*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*PicsArt-PhotoStudio*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*PolarrPhotoEditorAcademicEdition*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Prime*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*RoyalRevolt*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Shazam*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Sidia.LiveWallpaper*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*SlingTV*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Speed" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
#Get-AppxPackage -AllUsers "*SpotifyAB.SpotifyMusic*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null #Spotify (Music)
Get-AppxPackage -AllUsers "*Sway*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*TuneInRadio*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Twitter*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Viber*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*WinZipUniversal*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*Wunderlist*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "*XING*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
# Samsung Bloatware
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.1412377A9806A*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.NewVoiceNote*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCoLtd.SamsungNotes*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCoLtd.SamsungFlux*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.StudioPlus*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungWelcome*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungUpdate*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungSecurity1.2*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungScreenRecording*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungQuickSearch*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.SamsungCloudBluetoothSync*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.PCGallery*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
Get-AppxPackage -AllUsers "4AE8B7C2.BOOKING.COMPARTNERAPPSAMSUNGEDITION*" | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Out-Null
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
Get-Service "edgeupdate" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "edgeupdate" | Set-Service -StartupType Disabled | Out-Null
Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
Get-Service "edgeupdatem" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "edgeupdatem" | Set-Service -StartupType Disabled | Out-Null
Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
Write-Host "Disabled Microsoft Edge - Auto Update Services" -ForegroundColor Green
## Scheduled Tasks
Get-Scheduledtask "*edge*" -erroraction silentlycontinue | Disable-ScheduledTask | Out-Null
Write-Host "Disabled Microsoft Edge - Auto Start (Scheduled Task)" -ForegroundColor Green
## Auto Start
Set-Location HKLM:
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft" -Force -ErrorAction SilentlyContinue | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge" -Force -ErrorAction SilentlyContinue | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force -ErrorAction SilentlyContinue | Out-Null}
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value "0" -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Set-Location HKCU:
Set-Location "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\"
Remove-ItemProperty -Path. -Name "*MicrosoftEdge*" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Location "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Remove-ItemProperty -Path. -Name "*MicrosoftEdge*" -Force -ErrorAction SilentlyContinue | Out-Null
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
Start-Process -FilePath "$Env:WinDir\System32\OneDriveSetup.exe" -WorkingDirectory "$Env:WinDir\System32\" -ArgumentList "/uninstall" -ErrorAction SilentlyContinue
# x64
Start-Process -FilePath "$Env:WinDir\SysWOW64\OneDriveSetup.exe" -WorkingDirectory "$Env:WinDir\SysWOW64\" -ArgumentList "/uninstall" -ErrorAction SilentlyContinue
## Files Cleanup
# File Explorer - Navigation Bar
if((Test-Path -LiteralPath "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}") -ne $true) {  New-Item "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force -ErrorAction SilentlyContinue | Out-Null };
New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name '(default)' -Value 'OneDrive' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null;
New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null;
# AppData / Local
Remove-Item -Path "$env:localappdata\OneDrive" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
# ProgramData
Remove-Item -Path "$env:programdata\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue 
# Shortcuts
Remove-Item -Path "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction SilentlyContinue
# Program Files
Remove-Item -LiteralPath "C:\Program Files (x86)\Microsoft OneDrive" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "C:\Program Files\Microsoft OneDrive" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
## Scheduled Tasks
Get-ScheduledTask "*OneDrive*" | Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
## Services
$ODUPdaterService = Get-WmiObject -Class Win32_Service -Filter "Name='OneDrive Updater Service'"
$ODUPdaterService.delete() | Out-Null
## Registry
# Remove Previous Accounts/Sync Options
Remove-Item -LiteralPath "HKCU:\Software\Microsoft\OneDrive" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
# Remove previously set One Drive settings
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
# Remove Right Click Menu Context Options
Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\FileSyncHelper" -Recurse -Confirm:$false -Force -ErrorAction SilentlyContinue
# Remove from 'Default' user account
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

## Internet Explorer
if((Get-WMIObject win32_operatingsystem) | Where-Object {$_.Name -like "Microsoft Windows 10*"}) 
{
Write-Host "3.2.3 Internet Explorer" -ForegroundColor Green
# Addon 'Send to One Note'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Internet Explorer - Addon - REMOVED 'Send to One Note'" -ForegroundColor Green
# Addon 'OneNote Linked Notes'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Internet Explorer - Addon - REMOVED 'OneNote Linked Notes'" -ForegroundColor Green
# Addon 'Lync Click to Call'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" -Force -ErrorAction SilentlyContinue | Out-Null
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
Remove-Item -LiteralPath "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Send to OneNote.lnk" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "OneNote - REMOVED 'Send to OneNote'" -ForegroundColor Green

## Mozilla Firefox
# Scheduled Tasks
Get-ScheduledTask "*Firefox Default*" | Unregister-ScheduledTask -Confirm:$false
Write-Host "Firefox - Disabled 'Periodic requests to set as default browser'" -ForegroundColor Green

## 3.2.6 Teams (Home / Small Business)
Write-Host "3.2.6 Teams (Home / Small Business)" -ForegroundColor Green
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarMn' -Value '0' -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarMn' -Value '0' -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Teams (Home / Small Business) - Removed Taskbar Shortcut" -ForegroundColor Green

## 3.2.7 Teams (Work or School)
Write-Host "3.2.7 Teams (Work or School) - Disabled Auto Start" -ForegroundColor Green
Remove-ItemProperty -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "com.squirrel.Teams.Teams" -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "TeamsMachineInstaller" -Force -ErrorAction SilentlyContinue
Write-Host "Teams (Work or School) - Disabled Auto Start" -ForegroundColor Green
#endregion


<#############################################################################################################################>
# 4.0 Services and Scheduled Tasks
#region Windows 10 - Services and Scheduled Tasks
if((Get-WMIObject win32_operatingsystem) | Where-Object {$_.Name -like "Microsoft Windows 10*"}) 
{
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
Get-Service "MapsBroker" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "MapsBroker" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Bing Downloaded Maps Manager" -ForegroundColor Green
# Bluetooth (Setting to Manual in the event BT is used.)
Get-Service "BTAGService" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "BTAGService" | Set-Service -StartupType Manual | Out-Null
Get-Service "bthserv" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "bthserv" | Set-Service -StartupType Manual | Out-Null
Write-Host "Set to Manual: Bluetooth" -ForegroundColor Green
# Celluar Time
Get-Service "autotimesvc" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "autotimesvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Celluar Time" -ForegroundColor Green
# Parental Controls
Get-Service "WpcMonSvc" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "WpcMonSvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Parental Controls" -ForegroundColor Green
# Phone Service
Get-Service "PhoneSvc" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "PhoneSvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Phone Service" -ForegroundColor Green
# Portable Device Enumerator Service
Get-Service "WPDBusEnum" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "WPDBusEnum" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Portable Device Enumeration Service" -ForegroundColor Green
# Program Compatibility Assistant Service
Get-Service "PcaSvc" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "PcaSvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Program Compatibility Assistant Service" -ForegroundColor Green
# Remote Registry
Get-Service "RemoteRegistry" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "RemoteRegistry" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Remote Registry (Security Increased)" -ForegroundColor Green
# Retail Demo
Get-Service "RetailDemo" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "RetailDemo" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Retail Demo" -ForegroundColor Green
# Themes
Get-Service "Themes" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "Themes" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Touch Keyboard and Handwritting Panel" -ForegroundColor Green
# Windows Insider Service
Get-Service "wisvc" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "wisvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Insider Service" -ForegroundColor Green
# Windows Mobile Hotspot Service
Get-Service "icssvc" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "icssvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Mobile Hotspot Service" -ForegroundColor Green
# Windows Connected User Experiences and Telemetry #InTune
Get-Service "DiagTrack" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "DiagTrack" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Connected User Experiences and Telemetry" -ForegroundColor Green
# Windows Media Player Network Share
Get-Service "WMPNetworkSvc" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "WMPNetworkSvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Media Player Network Share" -ForegroundColor Green
# Windows Mixed Reality OpenXR Service
Get-Service "MixedRealityOpenXRSvc" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "MixedRealityOpenXRSvc" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Mixed Reality OpenXR Service" -ForegroundColor Green
# Windows Offline Files
Get-Service "CscService" | Stop-Service -ErrorAction SilentlyContinue | Out-Null
Get-Service "CscService" | Set-Service -StartupType Disabled | Out-Null
Write-Host "Disabled: Windows Offline Files" -ForegroundColor Green

# Scheduled Tasks
Write-Host "4.2 Scheduled Tasks" -ForegroundColor Green
Get-Scheduledtask "Proxy" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "SmartScreenSpecific" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Microsoft Compatibility Appraiser" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Consolidator" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "KernelCeipTask" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "UsbCeip" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "Microsoft-Windows-DiskDiagnosticDataCollector" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "GatherNetworkInfo" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "QueueReporting" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
Get-Scheduledtask "UpdateLibrary" -ErrorAction SilentlyContinue | Disable-ScheduledTask | Out-Null
}
else {
#Write-Host "Windows 10 Detected, Skipping."
}
#endregion


<#############################################################################################################################>
#region 5.0 Quality of Life
Write-Host "5.0 Quality of Life" -ForegroundColor Green


<### Windows 10 Tweaks ###>
if((Get-WMIObject win32_operatingsystem) | Where-Object {$_.Name -like "Microsoft Windows 10*"}) 
{
    if((Test-Path -LiteralPath "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32") -ne $true) {  New-Item "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force -ErrorAction SilentlyContinue | Out-Null }
    New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' -Name '(default)' -Value '' -PropertyType String  -Force -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Explorer: Restored W10 - Right Click Context Menu (Preference)" -ForegroundColor Green

    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Explorer: Disable Ads in File Explorer (Performance)" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" -Name "Enabled" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Cortana - Disabled 'Microsoft from getting to know you' (Privacy)" -ForegroundColor Green

Set-Itemproperty -Path 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value '0' -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Cortana: Disabled 'Activity Feed' in Start Menu (Privacy)" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Disabled Lockscreen suggestions and rotating pictures (Preference)" -ForegroundColor Green

Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Itemproperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Disabled Feedback Prompts (Privacy)" -ForegroundColor Green

Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Disabled Tips (Performance)" -ForegroundColor Green
}
else {
#Write-Host "Windows 11 Detected, Skipping."
}


<### Windows 11 Tweaks ###>
if((Get-WMIObject win32_operatingsystem) | Where-Object {$_.Name -like "Microsoft Windows 11*"}) 
{
if((Test-Path -LiteralPath "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32") -ne $true) {  New-Item "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' -Name '(default)' -Value '' -PropertyType String  -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Restored W10 - Right Click Context Menu (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_Layout' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Start Menu/Taskbar: Set Layout to reduce 'Recommened Apps' (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'EnableSnapBar' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Explorer: Disabled 'Snap Layout' Overlay (Preference)" -ForegroundColor Green

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -PropertyType "Dword" -Name "TaskbarAl" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value "0" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Start Menu/Taskbar: Alignment - Left (Preference)" -ForegroundColor Green
}
else {
#Write-Host "Windows 10 Detected, Skipping."
}


<### Windows 10/11 Tweaks ###>
# Take Ownership (Right Click Menu)
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\runas") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\*\shell\runas" -Force -ErrorAction SilentlyContinue | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\runas\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\*\shell\runas\command" -Force -ErrorAction SilentlyContinue | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\runas") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\runas" -Force -ErrorAction SilentlyContinue | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\runas\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\runas\command" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas\command' -Name '(default)' -Value 'cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas\command' -Name 'IsolatedCommand' -Value 'cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Name 'NoWorkingDirectory' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\command' -Name '(default)' -Value 'cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\command' -Name 'IsolatedCommand' -Value 'cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\' -Name 'Icon' -Value 'imageres.dll,-5311' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name 'Icon' -Value 'imageres.dll,-5311' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Adding File/Folder Take Ownership - Right Click Context Menu (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Priority' -Value 6 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Scheduling Category' -Value 'High' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Updating 'MMCSS' to prioritize games with higher system resources (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex' -Value -1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Network: Disabled Acceleration (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Disabled Fast Startup - Restored 'Fresh' Reboot (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Set paging file to clear at Shutdown (Privacy)" -ForegroundColor Green

# Source: https://www.thewindowsclub.com/disable-windows-10-startup-delay-startupdelayinmsec (Default=10, New Default=0)
if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize' -Name 'StartupDelayInMSec' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Disabled Startup Delay (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name '(default)' -Value 'Copy &as path' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'InvokeCommandOnSelection' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'VerbHandler' -Value '{f3d06e7c-1e45-4a26-847e-f9fcdee59be0}' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'VerbName' -Value 'copyaspath' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'Icon' -Value 'imageres.dll,-5302' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "File Explorer: Added 'Copy as Path' - Right Click Context Menu (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\pintohomefile") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\*\shell\pintohomefile" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\pintohomefile' -Name 'ProgrammaticAccessOnly' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "File Explorer: Removed 'Add to Favorites' - Right Click Context Menu (Preference)" -ForegroundColor Green

Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'Extended' -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'Icon' -Value 'imageres.dll,-5203' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "File Explorer: Added 'Run as different user' - Right Click Context Menu (Preference)" -ForegroundColor Green

# Sticky Keys
if((Test-Path -LiteralPath "HKCU:\Control Panel\Accessibility\StickyKeys") -ne $true) {  New-Item "HKCU:\Control Panel\Accessibility\StickyKeys" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name 'Flags' -Value '506' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
# Filter Keys
if((Test-Path -LiteralPath "HKCU:\Control Panel\Accessibility\ToggleKeys") -ne $true) {  New-Item "HKCU:\Control Panel\Accessibility\ToggleKeys" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Accessibility\ToggleKeys' -Name 'Flags' -Value '58' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Disabled Filter & Sticky Keys (Preference)" -ForegroundColor Green

Set-Itemproperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Disabled Troubleshooting 'Steps Recorder' (Performance)" -ForegroundColor Green

# Source: https://www.majorgeeks.com/content/page/irpstacksize.html (Default 15-20 connections, increased to 50)
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'IRPStackSize' -Value 48 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Network: Increased Performance for 'I/O Request Packet Stack Size (Performance)" -ForegroundColor Green

#Source: https://www.elevenforum.com/t/enable-or-disable-store-activity-history-on-device-in-windows-11.7812/ #Note: Potentially needed for InTune
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") -ne $true) {  New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "File Explorer: Disabled Activity Log (Privacy)" -ForegroundColor Green

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name "fDenyTSConnections" -value "0" -Force | Out-Null
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Host "Remote Desktop: Enabled (Preference)" -ForegroundColor Green

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -PropertyType "Dword" -Name "ToastEnabled" -Value "0" | Out-Null
Write-host "Windows: Disabled Toast Notifications (Performance)" -ForegroundColor Green

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -PropertyType "Dword" -Name "ShowTaskViewButton" -Value "0" -ErrorAction SilentlyContinue | Out-Null
Write-host "Start Menu/Taskbar: Removed 'Task View' Button (Preference)" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchBoxTaskbarMode" -Value "0" -Type "DWord" -Force | Out-Null
Write-host "Start Menu/Taskbar: Removed 'Search' Button (Preference)" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value "0" | Out-Null
Write-Host "Explorer: Enabled Display of Known File Extensions (Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Force -ErrorAction SilentlyContinue }
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowFrequent' -Value "0" -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Explorer: Disabled 'Recent Folders' in Quick Access (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Control Panel\Desktop\WindowMetrics") -ne $true) {  New-Item "HKCU:\Control Panel\Desktop\WindowMetrics" -Force -ErrorAction SilentlyContinue }
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop\WindowMetrics' -Name 'MinAnimate' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Explorer: Disabled Explorer Animations (Performance)" -ForegroundColor Green

# Add "Open with Powershell (Admin)" to Right Click Context Menu
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin" -Force -ErrorAction SilentlyContinue | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command" -Force -ErrorAction SilentlyContinue | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin" -Force -ErrorAction SilentlyContinue | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command" -Force -ErrorAction SilentlyContinue | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin" -Force -ErrorAction SilentlyContinue | Out-Null }
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command") -ne $true) {  New-Item "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command" -Force -ErrorAction SilentlyContinue | Out-Null }
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Classes\LibraryFolder\Background\shell\PowerShellAsAdmin" -Force -ErrorAction SilentlyContinue | Out-Null
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'Extended' -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'Extended' -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force -ErrorAction SilentlyContinue
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'Extended' -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value '' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLinkedConnections' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Explorer: Added 'Open with PowerShell (Admin)' - Right Click Context Menu (Preference)" -ForegroundColor Green

# Disable 'High Precision Event Timer' to prevent input lag/delays
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
Write-Host "Disabled 'High Precision Event Timer' - Formerly Multimedia Timer (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Control Panel\Desktop") -ne $true) {  New-Item "HKCU:\Control Panel\Desktop" -Force -ErrorAction SilentlyContinue | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Control" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop" -Name 'ForegroundLockTimeout' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop" -Name 'HungAppTimeout' -Value '400' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop" -Name 'WaitToKillAppTimeout' -Value '500' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'WaitToKillServiceTimeout' -Value '500' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Windows: Enabled Faster Shutdown (Performance)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowDriveLettersFirst' -Value 4 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Explorer: Drive letters PRE drive label [Example: '(C:) Windows vs. Windows (C:)]' (Preference)" -ForegroundColor Green

# Source: http://donewmouseaccel.blogspot.com/
if((Test-Path -LiteralPath "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse") -ne $true) {  New-Item "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse" -Force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseSpeed' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold1' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold2' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
if((Test-Path -LiteralPath "HKCU:\Control Panel\Mouse") -ne $true) {  New-Item "HKCU:\Control Panel\Mouse" -Force -ErrorAction SilentlyContinue }
if((Test-Path -LiteralPath "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse") -ne $true) {  New-Item "Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse" -Force -ErrorAction SilentlyContinue | Out-Null}
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value "([byte[]](0x	00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x	C0,0xCC,0x0C,0x00,0x00,0x00,0x00,0x00,0x	80,0x99,0x19,0x00,0x00,0x00,0x00,0x00,0x	40,0x66,0x26,0x00,0x00,0x00,0x00,0x00,0x	00,0x33,0x33,0x00,0x00,0x00,0x00,0x00))" -PropertyType Binary -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value "([byte[]](0x	00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0x70,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0xA8,0x00,0x00,0x00,0x00,0x00,0x	00,0x00,0xE0,0x00,0x00,0x00,0x00,0x00))" -PropertyType Binary -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseSpeed' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold1' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\.DEFAULT\Control Panel\Mouse' -Name 'MouseThreshold2' -Value '0' -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Mouse: Acceleration Fix (Performance/Preference)" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {  New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Value 1 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Explorer: Set Explorer to open with 'This PC' instead of 'Most Recent' (Preference)" -ForegroundColor Green

#Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "2"
#Write-Host "UAC: Disabled Prompt (Performance)" -ForegroundColor Green

#Set-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
#Write-Host "Explorer: Disabled 'Recent Files' in Explorer (Performance) [Skipped]" -ForegroundColor Yellow

#Set-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
#Write-Host "Explorer: Disabled Recent Files/Folders in Start Menu and Explorer (Performance) [Skipped]" -ForegroundColor Yellow
#endregion


<#############################################################################################################################>
#region 6.0 Performance
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

powercfg -setdcvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 4
powercfg -setacvalueindex SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 96996bc0-ad50-47ec-923b-6f41874dd9eb 4
Write-Host "Sleep Settings: Changed 'Sleep Button' turns off display" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings") -ne $true) {  New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -force -ErrorAction SilentlyContinue | Out-Null }
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowSleepOption' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowHibernateOption' -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
Write-Host "Sleep Settings: Disabled Sleep/Hibernate from Start Menu" -ForegroundColor Green

Set-Itemproperty -path "HKCU:\Control Panel\Desktop" -Name 'MenuShowDelay' -value '50'
Write-Host "Start Menu: Animation Time Reduced" -ForegroundColor Green

$ActiveNetworkAdapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name
$ActiveNetworkAdapterConverted = $ActiveNetworkAdapter.Name
Disable-NetAdapterPowerManagement -Name "$ActiveNetworkAdapterConverted" -DeviceSleepOnDisconnect -NoRestart | Out-Null
Write-Host "Network: Disabled Ethernet/Wireless Power Saving Settings" -ForegroundColor Green
#endregion


<#############################################################################################################################>
#region 7.0 Privacy
Write-Host "7.0 Privacy" -ForegroundColor Green
# App Permissions
Write-Host "App Permissions" -ForegroundColor Green
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" -ErrorAction SilentlyContinue
Set-Location HKLM:
New-Item -Path ".SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -ErrorAction SilentlyContinue
New-ItemProperty -Path ".SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value "1" -ErrorAction SilentlyContinue
New-Item -Path ".\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -ErrorAction SilentlyContinue
New-ItemProperty -Path ".\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "EnableStatus" -Type DWord -Value "1" -ErrorAction SilentlyContinue
# App Diagnostics
Write-Host "App Diagnostics" -ForegroundColor Green
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" -ErrorAction SilentlyContinue
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" -ErrorAction SilentlyContinue
#endregion

<#############################################################################################################################>
#region 8.0 Log - End
# Log Locally
"Script Duration" | Out-File -Append -FilePath $LogFile
$Timer.Elapsed | Select-Object Hours, Minutes, Seconds | Format-Table | Out-File -Append -FilePath $LogFile
$Timer.Stop()
$TimerFinal = $Timer.Elapsed | Select-Object Hours, Minutes, Seconds | Format-Table
Write-Host "8.0 Log: Script Duration" -ForegroundColor Green
$TimerFinal
Write-Host "Log file located at $LogFile" -ForegroundColor Yellow
#endregion