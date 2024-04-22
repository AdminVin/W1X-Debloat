<#############################################################################################################################>
#region 1.0 - Script Settings
$ErrorActionPreference = "SilentlyContinue"
### Log - Start
$PCName = (Get-CIMInstance CIM_ComputerSystem).Name
$Date = Get-Date
$LogFile = "C:\ProgramData\AV\Cleanup\$PCName.txt"
# Check if log directory exists
if (Test-Path -Path "C:\ProgramData\AV\Cleanup") {
    #Write-Host "Log folder exists, and does not need to be created." -ForegroundColor Green
} else {
    #Write-Host "Log folder does NOT exist, and will be created." -ForegroundColor Red
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
Write-Host "`n`n2.0 Diagnostics" -ForegroundColor Green
# Verbose Status Messaging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Value "1"
Write-Host "2.1 Verbose Status Messaging [Enabled]" -ForegroundColor Green
#endregion


<#############################################################################################################################>
#region 3.0 Applications
Write-Host "`n`n3.0 Applications" -ForegroundColor Green

#region Windows 10 - 3.1 Applications - Metro
Write-Host "3.1 Applications - Metro" -ForegroundColor Green
$Apps = @(
    "Microsoft.3DBuilder*",
    "Microsoft.549981C3F5F10*",
    "Microsoft.Appconnector*",
    "Microsoft.BingFinance*",
    "Microsoft.BingFoodAndDrink*",
    "Microsoft.BingHealthAndFitness*",
    "Microsoft.BingNews*",
    "Microsoft.BingSports*",
    "Microsoft.BingTranslator*",
    "Microsoft.BingTravel*",
    "Microsoft.CommsPhone*",
    "Microsoft.ConnectivityStore*",
    "Microsoft.WindowsFeedbackHub*",
    "Microsoft.GetHelp*",
    "Microsoft.Getstarted*",
    "Microsoft.Messaging*",
    "Microsoft.Microsoft3DViewer*",
    "Microsoft.MicrosoftOfficeHub*",
    "Microsoft.MicrosoftPowerBIForWindows*",
    "Microsoft.MixedReality.Portal*",
    "Microsoft.NetworkSpeedTest*",
    "Microsoft.Office.Sway*",
    "Microsoft.OneConnect*",
    "Microsoft.People*",
    "Microsoft.Print3D*",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.SkypeApp*",
    "MicrosoftTeams*",
    "Microsoft.Todos*",
    "Microsoft.Wallet*",
    "Microsoft.Whiteboard*",
    "Microsoft.WindowsMaps*",
    "*maps*",
    "Microsoft.WindowsPhone*",
    "Microsoft.WindowsReadingList*",
    "Microsoft.YourPhone*",
    "Microsoft.ZuneMusic*",
    "Microsoft.ZuneVideo*",
    "*ACGMediaPlayer*",
    "*ActiproSoftwareLLC*",
    "*AdobePhotoshopExpress*",
    "*Amazon.com.Amazon*",
    "*Asphalt8Airborne*",
    "*AutodeskSketchBook*",
    "*BubbleWitch3Saga*",
    "*CaesarsSlotsFreeCasino*",
    "*CandyCrush*",
    "*COOKINGFEVER*",
    "*CyberLinkMediaSuiteEssentials*",
    "*Disney*",
    "*DrawboardPDF*",
    "*Duolingo-LearnLanguagesforFree*",
    "*EclipseManager*",
    "*FarmVille2CountryEscape*",
    "*FitbitCoach*",
    "*Flipboard*",
    "*HiddenCity*",
    "*Hulu*",
    "*iHeartRadio*",
    "*Keeper*",
    "*Kindle*",
    "*LinkedInforWindows*",
    "*MarchofEmpires*",
    "*NYTCrossword*",
    "*OneCalendar*",
    "*Pandora*",
    "*PhototasticCollage*",
    "*PicsArt-PhotoStudio*",
    "*PolarrPhotoEditorAcademicEdition*",
    "*Prime*",
    "*RoyalRevolt*",
    "*Shazam*",
    "*Sidia.LiveWallpaper*",
    "*SlingTV*",
    "*Speed",
    "*Sway*",
    "*TuneInRadio*",
    "*Twitter*",
    "*Viber*",
    "*WinZipUniversal*",
    "*Wunderlist*",
    "*XING*",
    "SAMSUNGELECTRONICSCO.LTD.1412377A9806A*",
    "SAMSUNGELECTRONICSCO.LTD.NewVoiceNote*",
    "SAMSUNGELECTRONICSCoLtd.SamsungNotes*",
    "SAMSUNGELECTRONICSCoLtd.SamsungFlux*",
    "SAMSUNGELECTRONICSCO.LTD.StudioPlus*",
    "SAMSUNGELECTRONICSCO.LTD.SamsungWelcome*",
    "SAMSUNGELECTRONICSCO.LTD.SamsungUpdate*",
    "SAMSUNGELECTRONICSCO.LTD.SamsungSecurity1.2*",
    "SAMSUNGELECTRONICSCO.LTD.SamsungScreenRecording*",
    "SAMSUNGELECTRONICSCO.LTD.SamsungQuickSearch*",
    "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner*",
    "SAMSUNGELECTRONICSCO.LTD.SamsungCloudBluetoothSync*",
    "SAMSUNGELECTRONICSCO.LTD.PCGallery*",
    "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService*",
    "4AE8B7C2.BOOKING.COMPARTNERAPPSAMSUNGEDITION*"
)
foreach ($App in $Apps) {
    Write-Host " - Removed: "$App -ForegroundColor Green
    Remove-AppxPackage $App -AllUsers -ErrorAction SilentlyContinue
}

# Microsoft Store - Disable SILENT installation of NEW third party apps.
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Value "0"
# Disable future automatic installs/re-installs of factory/OEM Metro Apps.
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Value "0"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OEMPreInstalledAppsEnabled" -Value "0"
# Start Menu - Disable Metro app suggestions.
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value "0"
#endregion


#region Windows 10/11 - Applications - Desktop
Write-Host "3.2 Applications - Desktop" -ForegroundColor Green
# 3.2.1 Edge
Write-Host "3.2.1 Microsoft Edge" -ForegroundColor Green
## Services
Get-Service "edgeupdate" | Stop-Service | Out-Null
Get-Service "edgeupdate" | Set-Service -StartupType Disabled | Out-Null
Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdate" -Recurse -Confirm:$false -Force
Get-Service "edgeupdatem" | Stop-Service | Out-Null
Get-Service "edgeupdatem" | Set-Service -StartupType Disabled | Out-Null
Remove-Item -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\edgeupdatem" -Recurse -Confirm:$false -Force
Write-Host "Microsoft Edge - Auto Update Services [DISABLED]" -ForegroundColor Green
## Scheduled Tasks
Get-Scheduledtask "*edge*" | Disable-ScheduledTask | Out-Null
Write-Host "Microsoft Edge - Auto Start - Scheduled Task [DISABLED]" -ForegroundColor Green
## Auto Start
Set-Location HKLM:
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft") -ne $true) {New-Item "HKLM:\SOFTWARE\Policies\Microsoft" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge") -ne $true) {New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main") -ne $true) {New-Item "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null}
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Value "0" -PropertyType DWord -Force | Out-Null
Set-Location HKCU:
Set-Location "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run\"
Remove-ItemProperty -Path . -Name "*MicrosoftEdge*" -Force | Out-Null
Set-Location "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Remove-ItemProperty -Path . -Name "*MicrosoftEdge*" -Force | Out-Null
Set-Location C:/
Write-Host "Microsoft Edge - Auto Start - Startup Entry [DISABLED]" -ForegroundColor Green
# Tracking
Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'DoNotTrack' -Value '1'
Write-Host "Microsoft Edge - Tracking [DISABLED]" -ForegroundColor Green

# 3.2.2 OneDrive
Write-Host "3.2.2 One Drive" -ForegroundColor Green
# Detect if One Drive is being used currently (1 = Yes/Signed In | 0 = Never Signed In)
$ClientEverSignedInKey = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\OneDrive' -Name 'ClientEverSignedIn' -ErrorAction SilentlyContinue
if ($ClientEverSignedInKey -and $ClientEverSignedInKey.ClientEverSignedIn -eq 1) {
    # Result: 1 (One Drive is being Used)
    if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive')) {
        New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Force | Out-Null
    }
    # DisableFileSync
    if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -ErrorAction SilentlyContinue) -eq $null) {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -Value 0 -PropertyType DWord -Force | Out-Null
    } else {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -Value 0 | Out-Null
    }
    
    # DisableFileSyncNGSC
    if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -ErrorAction SilentlyContinue) -eq $null) {
        New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Value 0 -PropertyType DWord -Force | Out-Null
    } else {
        Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Value 0 | Out-Null
    }    
	Write-Host "3.2.2 Microsoft One Drive Removal [Skipped]" -ForegroundColor Yellow
} else {
    # Result: 0 (One Drive is NOT being used)
    	## Close OneDrive (if running in background)
		taskkill /f /im OneDrive.exe
		taskkill /f /im FileCoAuth.exe
	
		## Official Removal
		# x86
		Start-Process -FilePath "$Env:WinDir\System32\OneDriveSetup.exe" -WorkingDirectory "$Env:WinDir\System32\" -ArgumentList "/uninstall" | Out-Null
		# x64
		Start-Process -FilePath "$Env:WinDir\SysWOW64\OneDriveSetup.exe" -WorkingDirectory "$Env:WinDir\SysWOW64\" -ArgumentList "/uninstall" | Out-Null
	
		## Files Cleanup
		# File Explorer - Navigation Bar
		if((Test-Path -LiteralPath "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}") -ne $true) {New-Item "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Force | Out-Null}
		New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name '(default)' -Value 'OneDrive' -PropertyType String -Force | Out-Null
		New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Value "0" -PropertyType DWord -Force | Out-Null
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
		#########################################
        ### DISABLE ONE DRIVE FROM BEING USED ###
        #########################################
        if (-not (Test-Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive')) {
            New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Force | Out-Null
        }
        # DisableFileSync
        if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -ErrorAction SilentlyContinue) -eq $null) {
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -Value 1 -PropertyType DWord -Force | Out-Null
        } else {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -Value 1 | Out-Null
        }
        # DisableFileSyncNGSC
        if ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -ErrorAction SilentlyContinue) -eq $null) {
            New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Value 1 -PropertyType DWord -Force | Out-Null
        } else {
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Value 1 | Out-Null
        }
		Set-ItemProperty -Path "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSync" -Value "1" | Out-Null
		New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Value "1" -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
		Write-Host "3.2.2 Microsoft One Drive [Removed]" -ForegroundColor Yellow
}

## 3.2.3 Internet Explorer
Write-Host "3.2.3 Internet Explorer" -ForegroundColor Green
# Addon 'Send to One Note'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" -Force | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}" -Force | Out-Null
Write-Host "Internet Explorer - Addon - 'Send to One Note' [REMOVED]" -ForegroundColor Green
# Addon 'OneNote Linked Notes'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" -Force | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}" -Force | Out-Null
Write-Host "Internet Explorer - Addon - 'OneNote Linked Notes' [REMOVED]" -ForegroundColor Green
# Addon 'Lync Click to Call'
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" -Force | Out-Null
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}" -Force | Out-Null
Write-Host "Internet Explorer - Addon - 'Lync Click to Call' [REMOVED]" -ForegroundColor Green
# Addon IE to Edge Browser Helper Object
$existingTask = Get-ScheduledTask | Where-Object { $_.TaskName -like "Internet Explorer - IEtoEDGE Addon Removal" }
if ($existingTask -eq $null) {
    Get-ChildItem -Path "C:\Program Files (x86)\Microsoft\Edge\Application" -Recurse -Filter "BHO" | Remove-Item -Force -Recurse
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "Get-ChildItem -Path 'C:\Program Files (x86)\Microsoft\Edge\Application' -Recurse -Filter 'BHO' | Remove-Item -Force -Recurse"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Internet Explorer - IEtoEDGE Addon Removal" -Description "Removes the Internet Explorer Addon IEtoEDGE.  This will permit the use of Internet Explorer." -Principal $STPrin | Out-Null
}
Write-Host "Microsoft Edge - Addon: IE to Edge [DISABLED]" -ForegroundColor Green
Write-Host "Internet Explorer - Addon - 'IE to Edge' [REMOVED]" -ForegroundColor Green

## 3.2.4 One Note
Write-Host "3.2.4 One Note" -ForegroundColor Green
Remove-Item -LiteralPath "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Send to OneNote.lnk" -Force | Out-Null
Write-Host "OneNote - 'Send to OneNote' [REMOVED]" -ForegroundColor Green

## 3.2.5 Mozilla Firefox
Write-Host "3.2.5 Mozilla Firefox" -ForegroundColor Green
# Scheduled Tasks
Get-ScheduledTask "*Firefox Default*" | Unregister-ScheduledTask -Confirm:$false
Write-Host "Firefox - 'Periodic requests to set as default browser' [DISABLED]" -ForegroundColor Green

## 3.2.6 Teams (Home / Small Business)
Write-Host "3.2.6 Teams (Home / Small Business)" -ForegroundColor Green
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarMn' -Value '0' -PropertyType DWord -Force | Out-Null
Set-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarMn' -Value '0' -Force | Out-Null
Write-Host "Teams (Home / Small Business) - Taskbar Shortcut [REMOVED]" -ForegroundColor Green

## 3.2.7 Teams (Work or School)
Write-Host "3.2.7 Teams (Work or School) - Disabled Auto Start" -ForegroundColor Green
Remove-ItemProperty -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "com.squirrel.Teams.Teams" -Force
Remove-ItemProperty -LiteralPath "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "TeamsMachineInstaller" -Force
Write-Host "Teams (Work or School) - Auto Start [DISABLED]" -ForegroundColor Green

## 3.2.8 Tips/Ticks/Suggestions Pop Ups
Write-Host "3.2.8 Tips/Ticks/Suggestions Pop Ups" -ForegroundColor Green
# Source: https://www.elevenforum.com/t/disable-ads-in-windows-11.8004/
# Settings App Suggestions
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0 | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0 | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0 | Out-Null
Write-Host "Settings App Suggestions [DISABLED]" -ForegroundColor Green
# Windows Tips/Suggestions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0 | Out-Null
Write-Host "Windows Tips [DISABLED]" -ForegroundColor Green
# Windows 'Get most of out this device' Suggestions
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0 | Out-Null
Write-Host "Windows 'Getting most out of this device' [DISABLED]" -ForegroundColor Green
# Windows Welcome Experience
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0 | Out-Null
Write-Host "Windows 'Welcome' Experience [DISABLED]" -ForegroundColor Green
# Personalized Ads
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 | Out-Null
Write-Host "Windows Personalized Ads [DISABLED]" -ForegroundColor Green
# Tailored Experience
New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 | Out-Null
Write-Host "Windows Tailored Experience [DISABLED]" -ForegroundColor Green

## 3.2.9 Sysinternals Installation
Write-Host "3.2.9 Sysinternals" -ForegroundColor Green
New-Item "C:/users/$env:username/Temp/" -ItemType Directory
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/PSTools.zip" -OutFile "C:/users/$env:username/PSTools.zip"
Expand-Archive -Path "C:/users/$env:username/PSTools.zip" -DestinationPath "C:\Windows\System32" -Force
Remove-Item "C:/users/$env:username/PSTools.zip" -Force
Write-Host "Sysinternals Suite [INSTALLED]" -ForegroundColor Green
Write-Host "Official Website: https://learn.microsoft.com/en-us/sysinternals/" -ForegroundColor Green

## 3.3.0 Cortana
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value "0" -Force | Out-Null
Get-AppxPackage -AllUsers Microsoft.549981C3F5F10 | Remove-AppxPackage | Out-Null
Write-Host "3.3.0 Explorer: Cortana [DISABLED]" -ForegroundColor Green

## 3.4.0 Dynamic Lighting
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Lighting" -Name "AmbientLightingEnabled" -Value "0"
Write-Host "3.4.0 Microsoft Dynamic Lighting (RGB Fix) [Disabled]"
#endregion

#endregion


<#############################################################################################################################>
#region 4.0 - Services and Scheduled Tasks
Write-Host "`n`n4.0 - Services and Scheduled Tasks" -ForegroundColor Green
## Services
Write-Host "4.1 Services" -ForegroundColor Green
# Services - Disable
$services = @(
    "MapsBroker",						# Bing Downloaded Maps Manager
    "autotimesvc",						# Celluar Time
    "WpcMonSvc",						# Parental Controls
    "PhoneSvc",							# Phone Service
    "WPDBusEnum",						# Portable Device Enumerator Service
    "PcaSvc",							# Program Compatibility Assistant Service
    "RemoteRegistry",					# Remote Registry
    "RetailDemo",						# Retail Demo
    "Themes",							# Themes
    "wisvc",							# Windows Insider Service
    "icssvc",							# Windows Mobile Hotspot Service
    "DiagTrack",						# Windows Connected User Experiences and Telemetry (InTune related / Does not break sync)
	"WerSvc",							# Windows Error Reporting Service
    "WMPNetworkSvc",					# Windows Media Player Network Share
    "MixedRealityOpenXRSvc",			# Windows Mixed Reality OpenXR Service
    "WpnService",						# Windows Push Notification System Service
    "CscService"						# Windows Offline Files
)

foreach ($service in $services) {
    $serviceName = (Get-Service $service).DisplayName
    Get-Service $service | Stop-Service | Out-Null
    Get-Service $service | Set-Service -StartupType Disabled | Out-Null
    Write-Host " - Service: $serviceName [DISABLED]" -ForegroundColor Green
}
# Services - Set to Manual
$services = @(
    "BTAGService",						# Bluetooth (Setting to Manual in the event BT is used.)
    "bthserv"							# Bluetooth (Setting to Manual in the event BT is used.)
)

foreach ($service in $services) {
    $serviceName = (Get-Service $service).DisplayName
    Get-Service $service | Stop-Service | Out-Null
    Get-Service $service | Set-Service -StartupType Manual | Out-Null
    Write-Host " - Service: $serviceName [Set to Manual]" -ForegroundColor Green
}


## Scheduled Tasks
Write-Host "4.2 Scheduled Tasks" -ForegroundColor Green
$taskData = @(
    @{
        TaskName = "Proxy"
        DisplayName = "Proxy Task"
    },
    @{
        TaskName = "SmartScreenSpecific"
        DisplayName = "SmartScreen Specific Task"
    },
    @{
        TaskName = "Microsoft Compatibility Appraiser"
        DisplayName = "Microsoft Compatibility Appraiser Task"
    },
    @{
        TaskName = "Consolidator"
        DisplayName = "Consolidator Task"
    },
    @{
        TaskName = "KernelCeipTask"
        DisplayName = "Kernel CEIP Task"
    },
    @{
        TaskName = "UsbCeip"
        DisplayName = "USB CEIP Task"
    },
    @{
        TaskName = "Microsoft-Windows-DiskDiagnosticDataCollector"
        DisplayName = "Disk Diagnostic Data Collector Task"
    },
    @{
        TaskName = "GatherNetworkInfo"
        DisplayName = "Gather Network Info Task"
    },
    @{
        TaskName = "QueueReporting"
        DisplayName = "Queue Reporting Task"
    },
    @{
        TaskName = "UpdateLibrary"
        DisplayName = "Update Library Task"
    },
    @{
        TaskName = "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
        DisplayName = "Microsoft Compatibility Appraiser Task"
    },
    @{
        TaskName = "Microsoft\Windows\Application Experience\ProgramDataUpdater"
        DisplayName = "Program Data Updater Task"
    },
    @{
        TaskName = "Microsoft\Windows\Autochk\Proxy"
        DisplayName = "Proxy Task"
    },
    @{
        TaskName = "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
        DisplayName = "Consolidator Task"
    },
    @{
        TaskName = "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
        DisplayName = "USB CEIP Task"
    },
    @{
        TaskName = "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
        DisplayName = "Disk Diagnostic Data Collector Task"
    }
)

foreach ($taskInfo in $taskData) {
    $taskName = $taskInfo.TaskName
    $displayName = $taskInfo.DisplayName

    try {
        Disable-ScheduledTask -TaskName $taskName -ErrorAction Stop | Out-Null
        Write-Host " - Task: '$displayName' [DISABLED]" -ForegroundColor Green
    } catch {
        #
    }
}
#endregion

<#############################################################################################################################>
#region 5.0 - Quality of Life
Write-Host "`n`n5.0 Quality of Life" -ForegroundColor Green

<###################################### EXPLORER TWEAKS (Start) ######################################>

# Add "Take Ownership" to Right Click Context Menu
<# Old Code
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\runas") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\*\shell\runas" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\runas\command") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\*\shell\runas\command" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\runas") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\runas" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\runas\command") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\runas\command" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name 'NoWorkingDirectory' -Value "" -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas\command' -Name '(default)' -Value 'cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas\command' -Name 'IsolatedCommand' -Value 'cmd.exe /c takeown /f \"%1\" && icacls \"%1\" /grant administrators:F' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Name '(default)' -Value 'Take Ownership' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Name 'NoWorkingDirectory' -Value "" -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\command' -Name '(default)' -Value 'cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\command' -Name 'IsolatedCommand' -Value 'cmd.exe /c takeown /f \"%1\" /r /d y && icacls \"%1\" /grant administrators:F /t' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\' -Name 'Icon' -Value 'imageres.dll,-5311' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name 'Icon' -Value 'imageres.dll,-5311' -PropertyType String -Force | Out-Null
#>
# Removal of Old 'Take Ownership' (Broken)
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas\command' -Name 'IsolatedCommand' -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas\command' -Name '(default)' -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\runas\command" -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name 'Icon' -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name 'NoWorkingDirectory' -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\runas' -Name '(default)' -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\runas" -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\command' -Name 'IsolatedCommand' -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas\command' -Name '(default)' -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\runas\command" -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Name 'Icon' -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Name 'NoWorkingDirectory' -Force -ErrorAction SilentlyContinue
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\runas' -Name '(default)' -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\runas" -Force -ErrorAction SilentlyContinue
#Write-Host "Explorer: 'Take Ownership' - Right Click Context Menu [ADDED]" -ForegroundColor Green

Add "Open with Powershell 5.1 (Admin)" to Right Click Context Menu
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command" -Force | Out-Null}
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Classes\LibraryFolder\Background\shell\PowerShellAsAdmin" -Force | Out-Null
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") -ne $true) {New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'Extended' -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value "" -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'Extended' -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value "" -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name '(default)' -Value 'Open with PowerShell (Admin)' -PropertyType String -Force | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'Extended' -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'HasLUAShield' -Value "" -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLinkedConnections' -Value "1" -PropertyType DWord -Force | Out-Null
Write-Host "Explorer: 'Open with PowerShell 5.1 (Admin)' - Right Click Context Menu [ADDED]" -ForegroundColor Green


# Add "Open with Powershell 7 (Admin)" to Right Click Context Menu
# Install PS7
if (-not (Test-Path "C:\Program Files\PowerShell\7\pwsh.exe")) {
    New-Item -Path "C:\PSTemp" -ItemType Directory | Out-Null
    $PS7InstallerPath = "C:\PSTemp\PowerShell-7.3.9-win-x64.msi"  # Version 7.3.9
    $PS7InstallerURL = "https://github.com/PowerShell/PowerShell/releases/download/v7.4.1/PowerShell-7.4.1-win-x64.msi"
    Invoke-WebRequest -Uri $PS7InstallerURL -OutFile $PS7InstallerPath
    Start-Process -FilePath msiexec -ArgumentList "/i $PS7InstallerPath /qn" -Wait
    Remove-Item -Path "C:\PSTemp" -Recurse -Force | Out-Null
}
# Add to Right Click Context Menu
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin\command") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin\command" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin\command") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin\command" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin\command") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin\command" -Force | Out-Null}
Remove-Item -LiteralPath "HKLM:\SOFTWARE\Classes\LibraryFolder\Background\shell\PowerShell7AsAdmin" -Force -ErrorAction "SilentlyContinue" | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin' -Name '(default)' -Value 'Open with PowerShell 7 (Admin)' -PropertyType String -Force | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin' -Name 'Extended' -Force -ErrorAction "SilentlyContinue" | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin' -Name 'HasLUAShield' -Value "" -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin' -Name 'Icon' -Value 'powershell.exe' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs pwsh.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin' -Name '(default)' -Value 'Open with PowerShell 7 (Admin)' -PropertyType String -Force | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin' -Name 'Extended' -Force -ErrorAction "SilentlyContinue"  | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin' -Name 'HasLUAShield' -Value "" -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin' -Name 'Icon' -Value 'pwsh.exe' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs pwsh.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin' -Name '(default)' -Value 'Open with PowerShell 7 (Admin)' -PropertyType String -Force | Out-Null
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin' -Name 'Extended' -Force -ErrorAction "SilentlyContinue"  | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin' -Name 'HasLUAShield' -Value "" -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin' -Name 'Icon' -Value 'pwsh.exe' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs pwsh.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -PropertyType String -Force | Out-Null
Write-Host "Explorer: 'Open with PowerShell 7 (Admin)' - Right Click Context Menu [ADDED]" -ForegroundColor Green

# Add "Run as Different User" to Right Click Context Menu
Remove-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'Extended' -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'Icon' -Value 'imageres.dll,-5203' -PropertyType String -Force | Out-Null
Write-Host "Explorer: 'Run as different user' - Right Click Context Menu [ADDED]" -ForegroundColor Green

# Add "Copy as Path" to Right Click Context Menu
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name '(default)' -Value 'Copy &as path' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'InvokeCommandOnSelection' -Value "1" -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'VerbHandler' -Value '{f3d06e7c-1e45-4a26-847e-f9fcdee59be0}' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'VerbName' -Value 'copyaspath' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'Icon' -Value 'imageres.dll,-5302' -PropertyType String -Force | Out-Null
Write-Host "Explorer: 'Copy as Path' - Right Click Context Menu [ADDED]" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'EnableSnapBar' -Value "0" -PropertyType DWord -Force | Out-Null
Write-Host "Explorer: 'Snap Layout' Overlay [DISABLED]" -ForegroundColor Green

if ((Get-WMIObject win32_operatingsystem) | Where-Object { $_.Name -like "Microsoft Windows 11*" })
{
	if((Test-Path -LiteralPath "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32") -ne $true) {New-Item "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null}
	New-ItemProperty -LiteralPath 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32' -Name '(default)' -Value "" -PropertyType String  -Force | Out-Null
	Write-Host "Explorer: Windows 10 - Right Click Context Menu [RESTORED]" -ForegroundColor Green
}

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\pintohomefile") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\*\shell\pintohomefile" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\pintohomefile' -Name 'ProgrammaticAccessOnly' -Value "" -PropertyType String -Force | Out-Null
Write-Host "Explorer: 'Add to Favorites' - Right Click Context Menu [REMOVED]" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -force | Out-Null}
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Value "1" -PropertyType DWord -Force | Out-Null
Write-Host "Explorer: Set Explorer to open with 'This PC' instead of 'Most Recent'" -ForegroundColor Green

# Source: https://www.elevenforum.com/t/enable-or-disable-store-activity-history-on-device-in-windows-11.7812/ #Note: Potentially needed for InTune
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System") -ne $true) {New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Value "0" -PropertyType DWord -Force | Out-Null
Write-Host "Explorer: Activity Log [DISABLED]" -ForegroundColor Green

# Source: https://www.makeuseof.com/windows-disable-feedback-notifications/
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value "1" -Force | Out-Null
Write-Host "Explorer: Feedback Notifications [DISABLED]" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value "0" | Out-Null
Write-Host "Explorer: Display of Known File Extensions [ENABLED]" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer") -ne $true) {New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Force }
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowFrequent' -Value "0" -PropertyType DWord -Force | Out-Null
Write-Host "Explorer: 'Recent Folders' in Quick Access [DISABLED]" -ForegroundColor Green

# Remove Widgets/Install App Installer (app)/winget
# Reinstall Source: https://apps.microsoft.com/detail/windows-web-experience-pack/9MSSGKG348SP?hl=en-us&gl=US
Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe | Out-Null
winget uninstall --accept-source-agreements "Windows web experience pack" | Out-Null
Write-Host "Explorer: Widgets [REMOVED]" -ForegroundColor Green

New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLogonBackgroundImage' -Value "1" -PropertyType "DWord" -Force | Out-Null
Write-Host "Explorer: Background on Login Screen [DISABLED]" -ForegroundColor Green

# Source: https://www.kapilarya.com/disable-tips-and-suggestions-notifications-in-windows-11
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Value "1" -Force | Out-Null
Write-Host "Explorer: Tips [DISABLED]" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer") -ne $true) {New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowDriveLettersFirst' -Value 4 -PropertyType DWord -Force | Out-Null
Write-Host "Explorer: Drive letters PRE drive label [Example: '(C:) Windows vs. Windows (C:)]'" -ForegroundColor Green

# Source: https://documentation.n-able.com/N-central/userguide/Content/Automation/Policies/Diagnostics/pol_UACEnabled_Check.htm
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value "0"
Write-Host "Explorer: User Access Control - Prompt for Admins [DISABLED]" -ForegroundColor Green

Set-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name "PromptOnSecureDesktop" -Value "0"
Write-Host "Explorer: User Access Control - Desktop Dimming [DISABLED]" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AnimateMinimize" -Value "0"
if((Test-Path -LiteralPath "HKCU:\Control Panel\Desktop\WindowMetrics") -ne $true) {New-Item "HKCU:\Control Panel\Desktop\WindowMetrics" -Force}
New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "0" -PropertyType String -Force | Out-Null
Write-Host "Explorer: Animations - Window Minimizing [DISABLED]" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AnimateWindows" -Value "0"
Write-Host "Explorer: Animations - Window Opening/Closing [DISABLED]" -ForegroundColor Green

# Settings > Accessibility > Visual Effects > Transparency Effects
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value "0" | Out-Null
Write-Host "Explorer: Windows Transparency [Disabled]"

# Source: https://www.neowin.net/news/microsoft-windows-11-also-haunted-by-this-sata-bios-bug-just-like-windows-7-8-81-and-10/
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device' -Name 'TreatAsInternalPort' -Value @("0") -PropertyType MultiString -Force | Out-Null
Write-Host "Explorer: 'Safely Remove and Eject Media' for Intenal Drives [DISABLED]" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value "0" -Type DWORD -Force | Out-Null
Write-Host "Explorer: App Smart Screening [DISABLED]" -ForegroundColor Green

# Source: https://www.elevenforum.com/t/add-or-remove-gallery-in-file-explorer-navigation-pane-in-windows-11.14178/
New-Item -Path "HKCU:\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Force
New-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -PropertyType DWORD -Force | Out-Null
Write-Host "Explorer: 'Gallery' Shorcut [REMOVED]" -ForegroundColor Green

New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value "0" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value "0" | Out-Null
Write-Host "Explorer: Microsoft Co-Pilot SHORTCUT [REMOVED]" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value "0"
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value "0"
Write-Host "Explorer: Game Bar [DISABLED]" -ForegroundColor Green

# Right Click Context Menu "Convert to JPG"
$key = "HKLM:\SOFTWARE\Classes\SystemFileAssociations\.jfif\shell\ConvertToJPG"
if (!(Test-Path $key)) {
    $value = "Convert to JPG"
    $command = "powershell.exe Rename-Item -Path '%1' -NewName ('%1.jpg')"
    New-Item -Path $key -Force | Out-Null
    Set-ItemProperty -Path $key -Name "(Default)" -Value $value
    New-ItemProperty -LiteralPath $key -Name 'Icon' -Value 'shell32.dll,-16805' -PropertyType String -Force | Out-Null
    $commandKey = Join-Path $key "command"
    New-Item -Path $commandKey -Force | Out-Null
    Set-ItemProperty -Path $commandKey -Name "(Default)" -Value $command
    Write-Host "Explorer: File .JFIF to .JPG Conversion [ADDED]" -ForegroundColor Green}
<###################################### EXPLORER TWEAKS (End) ######################################>



<###################################### START MENU TWEAKS (Start) ######################################>

if ((Get-WMIObject win32_operatingsystem) | Where-Object { $_.Name -like "Microsoft Windows 11*" })
{
#Source: https://vhorizon.co.uk/windows-11-start-menu-layout-group-policy/
$ownerForm = New-Object System.Windows.Forms.Form
$result = [System.Windows.Forms.MessageBox]::Show($ownerForm, "Would you like your start bar and task bar icons aligned to the left?", "W1X Debloat - Start Bar/Task Bar", [System.Windows.Forms.MessageBoxButtons]::YesNo)
$ownerForm.Dispose()
if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
    if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
	New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value "0" -Type Dword -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value "0" -Force | Out-Null
	Write-Host "Start Menu: Alignment - Left" -ForegroundColor Green
	New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_Layout' -Value "1" -PropertyType DWord -Force | Out-Null
    Set-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_Layout' -Value "1" -Force | Out-Null
Write-Host "Start Menu: Set Layout to reduce 'Recommended Apps'" -ForegroundColor Green
} else { 
    if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced") -ne $true) {New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Force | Out-Null}
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value "1" -Type Dword -Force | Out-Null
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value "1" -Force | Out-Null
	Write-Host "Start Menu: Alignment - Center" -ForegroundColor Green
	New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_Layout' -Value "1" -PropertyType DWord -Force | Out-Null
    Set-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'Start_Layout' -Value "1" -Force | Out-Null
Write-Host "Start Menu: Set Layout to reduce 'Recommended Apps'" -ForegroundColor Green
}
}

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -PropertyType "Dword" -Name "ShowTaskViewButton" -Value "0" | Out-Null
Write-host "Start Menu: 'Task View' Button [HIDDEN]" -ForegroundColor Green

New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchBoxTaskbarMode" -Value "0" -Type "DWord" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchBoxTaskbarMode" -Value "0" -Force | Out-Null
Write-host "Start Menu: 'Search' Button [HIDDEN]" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value "0" -Force | Out-Null
Write-Host "Start Menu: Weather Widget [HIDDEN]" -ForegroundColor Green

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value "0" -Force | Out-Null
Write-Host "Start Menu: Animations - Icons [DISABLED]" -ForegroundColor Green

Set-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -value "1"
Write-Host "Start Menu: Animations - Appear/Load Time [REDUCED]" -ForegroundColor Green

# Add 'Devices and Printers' to Start Menu
$ShortcutPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("CommonPrograms"), "Devices & Printers.lnk")
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "shell:::{A8A91A66-3A7D-4424-8D24-04E180695C7A}"
$Shortcut.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WshShell) | Out-Null
Write-Host "Start Menu: 'Devices & Printers' [ADDED]" -ForegroundColor Green

<###################################### START MENU TWEAKS (End) ######################################>



<###################################### NETWORK TWEAKS (Start) ######################################>

$ActiveNetworkAdapter = Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object Name
$ActiveNetworkAdapterConverted = $ActiveNetworkAdapter.Name
Disable-NetAdapterPowerManagement -Name "$ActiveNetworkAdapterConverted" -DeviceSleepOnDisconnect -NoRestart | Out-Null
Write-Host "Network: Ethernet/Wireless Power Saving Settings [DISABLED]" -ForegroundColor Green

# Source: https://www.majorgeeks.com/content/page/irpstacksize.html (Default 15-20 connections, increased to 50)
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters") -ne $true) {New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"  -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'IRPStackSize' -Value 48 -PropertyType DWord -Force | Out-Null
Write-Host "Network: Increased Performance for 'I/O Request Packet Stack Size" -ForegroundColor Green

# Source: https://ttcshelbyville.wordpress.com/2017/10/14/network-throttling-index/
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile") -ne $true) {New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex' -Value -1 -PropertyType DWord -Force | Out-Null
if (-not (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Psched")) {New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Psched" -Force | Out-Null}
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Psched" -Name "NonBestEffortLimit" -Type Dword -Value "0" | Out-Null
Write-Host "Network: Throttling Index [DISABLED]" -ForegroundColor Green

<###################################### NETWORK TWEAKS (End) ######################################>



<###################################### WINDOWS TWEAKS (Start) ######################################>

# Disable 'High Precision Event Timer' to prevent input lag/delays
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
Write-Host "Windows: Disabled 'High Precision Event Timer' - Formerly Multimedia Timer" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games") -ne $true) {New-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'GPU Priority' -Value 8 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Priority' -Value 6 -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Scheduling Category' -Value 'High' -PropertyType String -Force | Out-Null
Write-Host "Windows: Updating 'MMCSS' to prioritize games with higher system resources" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power") -ne $true) {New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value "0" -PropertyType DWord -Force | Out-Null
Write-Host "Windows: Disabled Fast Startup - Restored 'Fresh' Reboot" -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management") -ne $true) {New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Value "1" -PropertyType DWord -Force | Out-Null
Write-Host "Windows: Set paging file to clear at Shutdown" -ForegroundColor Green

# Source: https://www.thewindowsclub.com/disable-windows-10-startup-delay-startupdelayinmsec (Default=10)
if ((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize") -ne $true) {
    New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
}
if ((Get-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -ErrorAction SilentlyContinue) -eq '') {
    New-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Value "5" -PropertyType DWord -Force | Out-Null
} else {
    Set-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Value "5" -Force | Out-Null
}
Write-Host "Windows: Reduced Startup Delay" -ForegroundColor Green

# MarkC's Mouse Acceleration Fix (DPI 100% Scale - Default)
# Source: http://donewmouseaccel.blogspot.com/
<# Disable 'Enhance pointer precision' #>
Set-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'MouseSpeed' -Value '0' | Out-Null
Set-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold1' -Value '0' | Out-Null
Set-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold2' -Value '0' | Out-Null
Write-Host "Windows: Mouse Acceleration - Disabled Enhance Pointer Precision" -ForegroundColor Green

$MouseSensitivity = (Get-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity").MouseSensitivity
IF((Get-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity").MouseSensitivity -eq 1) {
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x94,0x1E,0x05,0x00,0x00,0x00,0x00,0x00,0x28,0x3D,0x0A,0x00,0x00,0x00,0x00,0x00,0xBC,0x5B,0x0F,0x00,0x00,0x00,0x00,0x00,0x50,0x7A,0x14,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xEC,0xFF,0xDF,0x00,0x00,0x00,0x00,0x00,0xD8,0xFF,0xBF,0x01,0x00,0x00,0x00,0x00,0xC4,0xFF,0x9F,0x02,0x00,0x00,0x00,0x00,0xB0,0xFF,0x7F,0x03,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	Write-Host "Windows: Mouse 'Mouse Curve' adjusting to detected sensitivity $MouseSensitivity." -ForegroundColor Green;
}
IF((Get-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity").MouseSensitivity -eq 2) {
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xAE,0x1E,0x05,0x00,0x00,0x00,0x00,0x00,0x5C,0x3D,0x0A,0x00,0x00,0x00,0x00,0x00,0x0A,0x5C,0x0F,0x00,0x00,0x00,0x00,0x00,0xB8,0x7A,0x14,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0x6F,0x00,0x00,0x00,0x00,0x00,0xFE,0xFF,0xDF,0x00,0x00,0x00,0x00,0x00,0xFD,0xFF,0x4F,0x01,0x00,0x00,0x00,0x00,0xFC,0xFF,0xBF,0x01,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	Write-Host "Windows: Mouse 'Mouse Curve' adjusting to detected sensitivity $MouseSensitivity." -ForegroundColor Green;
}
IF((Get-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity").MouseSensitivity -eq 3) {
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFC,0xD6,0x03,0x00,0x00,0x00,0x00,0x00,0xF8,0xAD,0x07,0x00,0x00,0x00,0x00,0x00,0xF4,0x84,0x0B,0x00,0x00,0x00,0x00,0x00,0xF0,0x5B,0x0F,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0xFF,0x37,0x00,0x00,0x00,0x00,0x00,0xFE,0xFF,0x6F,0x00,0x00,0x00,0x00,0x00,0xFD,0xFF,0xA7,0x00,0x00,0x00,0x00,0x00,0xFC,0xFF,0xDF,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	Write-Host "Windows: Mouse 'Mouse Curve' adjusting to detected sensitivity $MouseSensitivity." -ForegroundColor Green;
}
IF((Get-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity").MouseSensitivity -eq 4) {
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xAE,0x1E,0x05,0x00,0x00,0x00,0x00,0x00,0x5C,0x3D,0x0A,0x00,0x00,0x00,0x00,0x00,0x0A,0x5C,0x0F,0x00,0x00,0x00,0x00,0x00,0xB8,0x7A,0x14,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xA8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xE0,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	Write-Host "Windows: Mouse 'Mouse Curve' adjusting to detected sensitivity $MouseSensitivity." -ForegroundColor Green;
}
IF((Get-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity").MouseSensitivity -eq 5) {
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x66,0x06,0x00,0x00,0x00,0x00,0x00,0xC0,0xCC,0x0C,0x00,0x00,0x00,0x00,0x00,0x20,0x33,0x13,0x00,0x00,0x00,0x00,0x00,0x80,0x99,0x19,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xA8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xE0,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	Write-Host "Windows: Mouse 'Mouse Curve' adjusting to detected sensitivity $MouseSensitivity." -ForegroundColor Green;
}
IF((Get-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity").MouseSensitivity -eq 6) {
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0xAE,0x07,0x00,0x00,0x00,0x00,0x00,0x08,0x5C,0x0F,0x00,0x00,0x00,0x00,0x00,0x0C,0x0A,0x17,0x00,0x00,0x00,0x00,0x00,0x10,0xB8,0x1E,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xF9,0xFF,0x37,0x00,0x00,0x00,0x00,0x00,0xF2,0xFF,0x6F,0x00,0x00,0x00,0x00,0x00,0xEB,0xFF,0xA7,0x00,0x00,0x00,0x00,0x00,0xE4,0xFF,0xDF,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force
	Write-Host "Windows: Mouse 'Mouse Curve' adjusting to detected sensitivity $MouseSensitivity." -ForegroundColor Green;
}
IF((Get-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity").MouseSensitivity -eq 7) {
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xB6,0xF5,0x08,0x00,0x00,0x00,0x00,0x00,0x6C,0xEB,0x11,0x00,0x00,0x00,0x00,0x00,0x22,0xE1,0x1A,0x00,0x00,0x00,0x00,0x00,0xD8,0xD6,0x23,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFA,0xFF,0x37,0x00,0x00,0x00,0x00,0x00,0xF4,0xFF,0x6F,0x00,0x00,0x00,0x00,0x00,0xEE,0xFF,0xA7,0x00,0x00,0x00,0x00,0x00,0xE8,0xFF,0xDF,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	Write-Host "Windows: Mouse 'Mouse Curve' adjusting to detected sensitivity $MouseSensitivity." -ForegroundColor Green;
}
IF((Get-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity").MouseSensitivity -eq 8) {
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x5C,0x3D,0x0A,0x00,0x00,0x00,0x00,0x00,0xB8,0x7A,0x14,0x00,0x00,0x00,0x00,0x00,0x14,0xB8,0x1E,0x00,0x00,0x00,0x00,0x00,0x70,0xF5,0x28,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xA8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xE0,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	Write-Host "Windows: Mouse 'Mouse Curve' adjusting to detected sensitivity $MouseSensitivity." -ForegroundColor Green;
}
IF((Get-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity").MouseSensitivity -eq 9) {
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0E,0x85,0x0B,0x00,0x00,0x00,0x00,0x00,0x1C,0x0A,0x17,0x00,0x00,0x00,0x00,0x00,0x2A,0x8F,0x22,0x00,0x00,0x00,0x00,0x00,0x38,0x14,0x2E,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xA8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xE0,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	Write-Host "Windows: Mouse 'Mouse Curve' adjusting to detected sensitivity $MouseSensitivity." -ForegroundColor Green;
}
IF((Get-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity").MouseSensitivity -eq 10) {
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseXCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xC0,0xCC,0x0C,0x00,0x00,0x00,0x00,0x00,0x80,0x99,0x19,0x00,0x00,0x00,0x00,0x00,0x40,0x66,0x26,0x00,0x00,0x00,0x00,0x00,0x00,0x33,0x33,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Mouse' -Name 'SmoothMouseYCurve' -Value ([byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x38,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x70,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xA8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xE0,0x00,0x00,0x00,0x00,0x00)) -PropertyType Binary -Force | Out-Null
	Write-Host "Windows: Mouse 'Mouse Curve' adjusting to detected sensitivity $MouseSensitivity." -ForegroundColor Green;
}

# Sticky Keys
if((Test-Path -LiteralPath "HKCU:\Control Panel\Accessibility\StickyKeys") -ne $true) {New-Item "HKCU:\Control Panel\Accessibility\StickyKeys" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name 'Flags' -Value '506' -PropertyType String -Force | Out-Null

# Filter Keys
if((Test-Path -LiteralPath "HKCU:\Control Panel\Accessibility\ToggleKeys") -ne $true) {New-Item "HKCU:\Control Panel\Accessibility\ToggleKeys" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Accessibility\ToggleKeys' -Name 'Flags' -Value '58' -PropertyType String -Force | Out-Null
Write-Host "Windows: Filter & Sticky Keys [DISABLED]" -ForegroundColor Green

Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Value "1" -Force | Out-Null
Write-Host "Windows: Troubleshooting 'Steps Recorder' [DISABLED]" -ForegroundColor Green

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -name "fDenyTSConnections" -value "0" -Force | Out-Null
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
Write-Host "Windows: Remote Desktop [ENABLED]" -ForegroundColor Green

Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Force | Out-Null
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -PropertyType "Dword" -Name "ToastEnabled" -Value "0" | Out-Null
Write-host "Windows: Toast Notifications [DISABLED]" -ForegroundColor Green

# Lockscreen suggestions/rotating pictures
if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager") -ne $true) {New-Item "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null}
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value "0" -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value "0" -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value "0" -PropertyType DWord -Force | Out-Null
Write-Host "Windows: Lockscreen suggestions and rotating pictures [DISABLED]" -ForegroundColor Green

if((Test-Path -LiteralPath "HKCU:\Control Panel\Desktop") -ne $true) {New-Item "HKCU:\Control Panel\Desktop" -Force | Out-Null}
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control") -ne $true) {New-Item "HKLM:\SYSTEM\CurrentControlSet\Control" -Force | Out-Null}
New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop" -Name 'ForegroundLockTimeout' -Value "0" -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop" -Name 'HungAppTimeout' -Value '400' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop" -Name 'WaitToKillAppTimeout' -Value '500' -PropertyType String -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'WaitToKillServiceTimeout' -Value '500' -PropertyType String -Force | Out-Null
Write-Host "Windows: Faster Shutdown [ENABLED]" -ForegroundColor Green

# 'Microsoft from getting to know you'
if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System") -ne $true) {New-Item "HKCU:\SOFTWARE\Policies\Microsoft\Windows\System" -Force | Out-Null}
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value "0" -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value "0" -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value "0" -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value "0" -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value "0" -Force | Out-Null
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Value "0" -PropertyType DWord -Force | Out-Null
Write-Host "Windows: 'Microsoft from getting to know you' [DISABLED]" -ForegroundColor Green

# Split Service Host Threshold for increased reliablity
# Source: https://www.tenforums.com/tutorials/94628-change-split-threshold-svchost-exe-windows-10-a.html
$RamInKB = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Value $RamInKB -Force
Write-Host "Windows: Reduced Service Host Threshold [UPDATED]" -ForegroundColor Green

# Windows Update Delivery Optimization - Disable sending/receiving updates from PCs on local network.
# Source: https://www.elevenforum.com/t/turn-on-or-off-windows-update-delivery-optimization-in-windows-11.3136
if((Test-Path -LiteralPath "Registry::\HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings") -ne $true) {New-Item "Registry::\HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" -Force | Out-Null}
New-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' -Name 'DownloadMode' -Value "0" -PropertyType DWord -Force | Out-Null
Set-ItemProperty -LiteralPath 'Registry::\HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' -Name 'DownloadMode' -Value "0" -Force | Out-Null
Write-Host "Windows: Update Delivery Optimization - Direct Download [UPDATED]" -ForegroundColor Green

# Windows > Display 'Ease cursor Movement between displays'
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Cursors' -Name 'CursorDeadzoneJumpingSetting' -Value "0" -PropertyType DWord -Force | Out-Null
Set-ItemProperty -LiteralPath 'HKCU:\Control Panel\Cursors' -Name 'CursorDeadzoneJumpingSetting' -Value "0" -Force | Out-Null

<###################################### WINDOWS TWEAKS (End) ######################################>



<###################################### TEST TWEAKS (Start) ######################################>

#Set-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value "1" -Force | Out-Null
#Write-Host "Explorer: Disabled 'Recent Files' in Explorer [Skipped]" -ForegroundColor Yellow

#Set-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value "1" -Force | Out-Null
#Write-Host "Explorer: Disabled Recent Files/Folders in Start Menu and Explorer [Skipped]" -ForegroundColor Yellow

<#
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Value "0"
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting' -Value 393241
New-ItemProperty -LiteralPath 'HKCU:\Control Panel\Desktop' -Name 'UserPreferencesMask' -Value ([byte[]](0x10,0x32,0x07,0x80,0x10,0x00,0x00,0x00)) -PropertyType Binary -Force
Write-Host "Explorer: Set Optimal Visual Settings" -ForegroundColor Green
#>

<###################################### TEST TWEAKS (Ened) ######################################>
#endregion


<#############################################################################################################################>
#region 6.0 - Power Settings
Write-Host "`n`n6.0 Power Settings" -ForegroundColor Green
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
Write-Host "Sleep Settings: Hibernate [DISABLED]" -ForegroundColor Green

powercfg -setacvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg -setdcvalueindex 381b4222-f694-41f0-9685-ff5bb260df2e 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
Write-Host "Sleep Settings: 'Closing Lid' action to turn off screen" [CHANGED] -ForegroundColor Green

if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings") -ne $true) {New-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowSleepOption' -Value "0" -PropertyType DWord -Force | Out-Null
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowHibernateOption' -Value "0" -PropertyType DWord -Force | Out-Null
Write-Host "Sleep Settings: Sleep/Hibernate from Start Menu [DISABLED]" -ForegroundColor Green
#endregion


<#############################################################################################################################>
#region 7.0 - Privacy
Write-Host "`n`n7.0 Privacy" -ForegroundColor Green
## Applications
Write-Host "7.1 Applications" -ForegroundColor Green
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" | Out-Null
Set-Location HKLM:
New-Item -Path ".SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" | Out-Null
New-ItemProperty -Path ".SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value "1"
New-Item -Path ".\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" | Out-Null
New-ItemProperty -Path ".\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "EnableStatus" -Type DWord -Value "1" | Out-Null
Write-Host "Applications - Location Permissions [DISABLED]" -ForegroundColor Green
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" | Out-Null
Write-Host "Applications - Diagnostics [DISABLED]" -ForegroundColor Green

Write-Host "7.2 Keyboard" -ForegroundColor Green
# Disable 'Improve inking and typing recognition'
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowLinguisticDataCollection") -ne $true) {New-Item "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowLinguisticDataCollection" | Out-Null};
New-ItemProperty -LiteralPath "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowLinguisticDataCollection" -Name "value" -Value "0" -PropertyType DWord -Force | Out-Null
if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Input\TIPC") -ne $true) {New-Item "HKCU:\Software\Microsoft\Input\TIPC" -Force | Out-Null};
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Input\TIPC' -Name 'Enabled' -Value "0" -PropertyType DWord -Force | Out-Null
Write-Host "Keyboard - Improved Inking and Typing Reconition [DISABLED]" -ForegroundColor Green

Write-Host "7.3 Clipboard" -ForegroundColor Green
if((Test-Path -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard") -ne $true) {New-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" -Force | Out-Null};
New-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard' -Name 'Disabled' -Value "1" -PropertyType DWord -Force | Out-Null
Write-Host "Clipboard - 'Smart Clipboard' [DISABLED]" -ForegroundColor Green

Write-Host "7.4 Telemetry" -ForegroundColor Green #InTune Required
# Disable Tailored Experiences With Diagnostic Data
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -type "Dword" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Value "0"
# Disable Telemetry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value "0" | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "MaxTelemetryAllowed" -Type DWord -Value "0" | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value "0" | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value "0" | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value "0" | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value "0" | Out-Null
Write-Host "Windows: Telementry [DISABLED]" -ForegroundColor Green

# Firewall Block
# Inbound - Check
$inboundRuleExists = Get-NetFirewallRule -DisplayName "Telementry Block - Inbound" -ErrorAction SilentlyContinue
# Inbound - Add
if (-not $inboundRuleExists) {
    netsh advfirewall firewall add rule name="Telementry Block - Inbound" dir=in action=block remoteip=134.170.30.202,137.116.81.24,157.56.106.189,184.86.53.99,2.22.61.43,2.22.61.66,204.79.197.200,23.218.212.69,65.39.117.23,65.55.108.23,64.4.54.254 enable=yes
}
# Outbound - Check
$outboundRuleExists = Get-NetFirewallRule -DisplayName "Telementry Block - Outbound" -ErrorAction SilentlyContinue
# Outbound - Add
if (-not $outboundRuleExists) {
    netsh advfirewall firewall add rule name="Telementry Block - Outbound" dir=out action=block remoteip=65.55.252.43,65.52.108.29,191.232.139.254,65.55.252.92,65.55.252.63,65.55.252.93,65.55.252.43,65.52.108.29,194.44.4.200,194.44.4.208,157.56.91.77,65.52.100.7,65.52.100.91,65.52.100.93,65.52.100.92,65.52.100.94,65.52.100.9,65.52.100.11,168.63.108.233,157.56.74.250,111.221.29.177,64.4.54.32,207.68.166.254,207.46.223.94,65.55.252.71,64.4.54.22,131.107.113.238,23.99.10.11,68.232.34.200,204.79.197.200,157.56.77.139,134.170.58.121,134.170.58.123,134.170.53.29,66.119.144.190,134.170.58.189,134.170.58.118,134.170.53.30,134.170.51.190,157.56.121.89,134.170.115.60,204.79.197.200,104.82.22.249,134.170.185.70,64.4.6.100,65.55.39.10,157.55.129.21,207.46.194.25,23.102.21.4,173.194.113.220,173.194.113.219,216.58.209.166,157.56.91.82,157.56.23.91,104.82.14.146,207.123.56.252,185.13.160.61,8.254.209.254,198.78.208.254,185.13.160.61,185.13.160.61,8.254.209.254,207.123.56.252,68.232.34.200,65.52.100.91,65.52.100.7,207.46.101.29,65.55.108.23,23.218.212.69 enable=yes
}
Write-Host "Windows: Telementry Internet Connection [DISABLED]" -ForegroundColor Green
#endregion


<#############################################################################################################################>
#region 8.0 - Script Settings
### Log - End
# Log Locally
"Script Duration" | Out-File -Append -FilePath $LogFile
$Timer.Elapsed | Select-Object Hours, Minutes, Seconds | Format-Table | Out-File -Append -FilePath $LogFile
$Timer.Stop()
$TimerFinal = $Timer.Elapsed | Select-Object Hours, Minutes, Seconds | Format-Table
Write-Host "`n`n8.0 Log: Script Duration" -ForegroundColor Green
$TimerFinal
Write-Host "Log file located at $LogFile" -ForegroundColor Yellow
#endregion


<#############################################################################################################################>
#region 9.0 - Notify User / Reboot
Write-Host " "
Write-Host " "
Write-Host "***************************************************************" -ForegroundColor Green
Write-Host "*                                                             *" -ForegroundColor Green
Write-Host "*             W1X Debloat v2.0 has finished!                  *" -ForegroundColor Green
Write-Host "*                                                             *" -ForegroundColor Green
Write-Host "***************************************************************" -ForegroundColor Green
$ownerForm = New-Object System.Windows.Forms.Form
$result = [System.Windows.Forms.MessageBox]::Show($ownerForm, "Reboot now to apply changes?", "W1X Debloat - Reboot", [System.Windows.Forms.MessageBoxButtons]::YesNo)
$ownerForm.Dispose()
if ($result -eq [System.Windows.Forms.DialogResult]::Yes) {
    Write-Host "Rebooting now!" -ForegroundColor Green
    Restart-Computer -Force
} else {
    Write-Host "`n`nYou can close this window." -ForegroundColor Green
}

#endregion