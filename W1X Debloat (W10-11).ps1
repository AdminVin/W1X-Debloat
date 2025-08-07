$SV = "3.04"
<#############################################################################################################################>
<# 
[>] Change Log
2025-08-07 - v3.04
    - Misc Code cleanup/fixes.
2025-08-03 - v3.03
    - Updated Hyper-V tweak, skipping if Docker is installed.
    - Updated OneDrive detection and cleaned up output.
2025-07-07 - v3.02
    - Added PowerShell 7 Updater
    - Removed 'Ask Co-Pilot' from Right Click Context Menu.
2025-06-20 - v3.01
    - Fixed progress bar bug (being stuck on screen, post operation).
2025-06-19 - v3.00
    - Updated method to detect if OneDrive is signed in and syncing.
    - Updated log to include space restored.
        - Log Location: C:/ProgramData/AV/Cleanup
    - Rewrote all registry modifications, to process faster with a function.
    - Updated Metro apps list for removal.
    - Metro apps will be removed system wide (all users).
    - Updated power plan from "Balanced" to "High Performance" while retaining settings.
    - Added Sysinternals "Autoruns" & "Autoruns64" to install.
        - Start > Run > autoruns to quick launch.
    - Updated Scheduled Tasks & Services method.
       - Removed Windows Media Player Sharing service.
    - Updated network tweaks: NetDMA; enabled RSS/DCA; set CTCP for optimized throughput and reduced latency.
2022-07-01 - v1.00
    - Initial creation of script.
#>


<#############################################################################################################################>
#region 1.0 - Script Settings
## Variables
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"            # Disable Progress Bars
## Functions
function Set-Registry {
    param (
        [string]$Path,
        [string]$Name,
        [Parameter(ValueFromPipeline = $true)]
        [Object]$Value,
        [ValidateSet('String','ExpandString','Binary','DWord','MultiString','QWord')]
        [string]$Type,
        [ValidateSet('Path','Value')]
        [string]$Remove
    )
    # Removal Check
    if ($Remove -eq 'Path') {
        if (Test-Path $Path) {
            Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
        }
        return
    }
    if ($Remove -eq 'Value') {
        if (Test-Path $Path) {
            if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
            }
        }
        return
    }
    # Path Check
    if (-not (Test-Path $Path)) {
        $null = New-Item -Path $Path -Force
    }
    # Item Check
    if (-not (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue)) {
        $null = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force
    } else {
        $null = Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    }
}

function Test-OneDriveSyncing {
    $configPaths = Get-ChildItem "$env:LOCALAPPDATA\Microsoft\OneDrive\settings" -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path "$($_.FullName)\ClientPolicy.ini" }

    foreach ($path in $configPaths) {
        $ini = "$($path.FullName)\ClientPolicy.ini"
        if (
            (Get-Process -Name "OneDrive" -ErrorAction SilentlyContinue) -and
            (Get-Content $ini -ErrorAction SilentlyContinue | Select-String "UserSID=")
        ) {
            return $true
        }
    }
    return $false
}
### Log - Start
$PCName = (Get-CIMInstance CIM_ComputerSystem).Name
$Date = Get-Date
$LogFile = "C:\ProgramData\AV\Cleanup\$PCName.txt"
if (!(Test-Path -Path "C:\ProgramData\AV\Cleanup")) { New-Item "C:\ProgramData\AV\Cleanup" -Type Directory | Out-Null }
if (-not (Select-String -Path $LogFile -Pattern "#" -Quiet)) { Remove-Item -Path $LogFile -Force -ErrorAction SilentlyContinue | Out-Null }
$Date | Out-File -Append -FilePath $LogFile
Write-Host "1.0 Log: Script started at $Date" -ForegroundColor Green
$Timer = [System.Diagnostics.Stopwatch]::StartNew()
# Free Space - Retrieve Existing Free Space
$FreeSpaceBefore = (Get-PSDrive -Name C).Free / 1GB
Write-Host " - Disk Space Free (before): $("{0:N2} GB" -f $FreeSpaceBefore)" -ForegroundColor Yellow
#endregion


<#############################################################################################################################>
#region 2.0  - Diagnostics
Write-Host "`n`n2.0 Diagnostics" -ForegroundColor Green
# Verbose Status Messaging
Set-Registry -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -Type Dword -Value "1"
Write-Host "2.1 Verbose Status Messaging [Enabled]" -ForegroundColor Green
#endregion


<#############################################################################################################################>
#region 3.0 Applications
Write-Host "`n`n3.0 Applications" -ForegroundColor Green

#region Windows 10 - 3.1 Applications - Metro
Write-Host "3.1 Applications - Metro" -ForegroundColor Green
$Apps = @(
    # Microsoft - General Bloatware
    "Microsoft.3DBuilder*",                                     # 3D Printing App
    "Microsoft.549981C3F5F10*",                                 # Cortana Listen Component
    "Microsoft.Appconnector*",                                  # App Linking Service
    "Microsoft.BingFinance*",                                   # Finance App
    "Microsoft.BingFoodAndDrink*",                              # Food & Drink Guide
    "Microsoft.BingHealthAndFitness*",                          # Health & Fitness App
    "Microsoft.BingNews*",                                      # News App
    "Microsoft.BingSports*",                                    # Sports Scores App
    "Microsoft.BingTranslator*",                                # Translator App
    "Microsoft.BingTravel*",                                    # Travel App
    "*Cortana*",                                                # Voice Assistant
    "*Clipchamp*",                                              # Video Editor
    "Microsoft.CommsPhone*",                                    # Phone Communications
    "Microsoft.ConnectivityStore*",                             # Network Settings Storage
    "Microsoft.ECApp",                                          # Ease of Access (OOBE)
    "Microsoft.Edge.GameAssist",                                # Edge Gaming Overlay
    "Microsoft.WindowsFeedbackHub*",                            # Send Feedback to Microsoft
    "Microsoft.GetHelp*",                                       # Microsoft Support App
    "Microsoft.Getstarted*",                                    # Introductory Guide
    "*maps*",                                                   # Mapping App
    "Microsoft.Messaging*",                                     # SMS Messaging App
    "Microsoft.Windows.NarratorQuickStart",                     # Narrator Tutorial
    "Microsoft.Microsoft3DViewer*",                             # View 3D Models
    "Microsoft.MicrosoftOfficeHub*",                            # Office Promotions
    "Microsoft.MicrosoftPowerBIForWindows*",                    # PowerBI Desktop
    "Microsoft.MixedReality.Portal*",                           # Mixed Reality Setup
    "Microsoft.NetworkSpeedTest*",                              # Network Speed Test
    "Microsoft.Office.Sway*",                                   # Sway Presentation Tool
    "Microsoft.OneConnect*",                                    # Device Linking
    "Microsoft.People*",                                        # Contacts Manager
    "Microsoft.PowerAutomateDesktop",                           # RPA Tool
    "Microsoft.Print3D*",                                       # 3D Print Utility
    "Microsoft.MicrosoftSolitaireCollection",                   # Solitaire Game
    "Microsoft.SkypeApp*",                                      # Skype Chat App
    "MicrosoftTeams*",                                          # Teams for Home
    "Microsoft.Todos*",                                         # To Do List App
    "Microsoft.Wallet*",                                        # Payment Wallet
    "Microsoft.WidgetsPlatformRuntime",                         # Widgets Engine
    "Microsoft.Whiteboard*",                                    # Virtual Whiteboard
    "MicrosoftWindows.Client.WebExperience",                    # Widgets & Search UI
    "Microsoft.WindowsMaps*",                                   # Mapping App
    "Microsoft.WindowsPhone*",                                  # Phone Companion
    "Microsoft.WindowsReadingList*",                            # Reading List App
    "Microsoft.YourPhone*",                                     # Phone Link App
    "Microsoft.ZuneMusic",                                      # Groove Music
    # Microsoft - Random Bloatware
    "*ACGMediaPlayer*",                                         # Media Player
    "*ActiproSoftwareLLC*",                                     # Syntax Editor Component
    "*AdobePhotoshopExpress*",                                  # Photoshop Express
    "*Amazon.com.Amazon*",                                      # Amazon Shopping
    "*Asphalt8Airborne*",                                       # Car Racing Game
    "*AutodeskSketchBook*",                                     # Drawing App
    "*BubbleWitch3Saga*",                                       # Puzzle Game
    "*CaesarsSlotsFreeCasino*",                                 # Casino Game
    "*CandyCrush*",                                             # Puzzle Game
    "*COOKINGFEVER*",                                           # Cooking Game
    "*CyberLinkMediaSuiteEssentials*",                          # Media Suite
    "*Disney*",                                                 # Disney App
    "*DrawboardPDF*",                                           # PDF Editor
    "*Duolingo-LearnLanguagesforFree*",                         # Language Learning
    "*EclipseManager*",                                         # Education Tool
    "*FarmVille2CountryEscape*",                                # Farming Game
    "*FitbitCoach*",                                            # Fitness Coach
    "*Flipboard*",                                              # News Aggregator
    "*HiddenCity*",                                             # Hidden Object Game
    "*Hulu*",                                                   # Streaming App
    "*iHeartRadio*",                                            # Radio Streaming
    "*Keeper*",                                                 # Password Manager
    "*Kindle*",                                                 # eBook Reader
    "*LinkedInforWindows*",                                     # LinkedIn App
    "*MarchofEmpires*",                                         # Strategy Game
    "*NYTCrossword*",                                           # Crossword Puzzle
    "*OneCalendar*",                                            # Calendar App
    "*Pandora*",                                                # Music Streaming
    "*PhototasticCollage*",                                     # Photo Collage
    "*PicsArt-PhotoStudio*",                                    # Photo Editor
    "*PolarrPhotoEditorAcademicEdition*",                       # Photo Editor
    "*Prime*",                                                  # Amazon Prime
    "*RoyalRevolt*",                                            # Action Strategy
    "*Shazam*",                                                 # Music Identifier
    "*Sidia.LiveWallpaper*",                                    # Live Wallpaper
    "*SlingTV*",                                                # Live TV App
    "*Speed*",                                                  # Likely Racing Game
    "*Sway*",                                                   # Presentation App
    "*TuneInRadio*",                                            # Radio Streaming
    "*Twitter*",                                                # Twitter Client
    "*Viber*",                                                  # Messaging App
    "*WinZipUniversal*",                                        # Archive Tool
    "*Wunderlist*",                                             # Task Manager
    "*XING*",                                                   # Business Network
    "*zune*",                                                   # Zune Music/Video
    # Samsung - Bloatware
    "SAMSUNGELECTRONICSCO.LTD.1412377A9806A*",                  # Samsung App
    "SAMSUNGELECTRONICSCO.LTD.NewVoiceNote*",                   # Voice Notes
    "SAMSUNGELECTRONICSCoLtd.SamsungNotes*",                    # Samsung Notes
    "SAMSUNGELECTRONICSCoLtd.SamsungFlux*",                     # Unknown Samsung App
    "SAMSUNGELECTRONICSCO.LTD.StudioPlus*",                     # Video Editor
    "SAMSUNGELECTRONICSCO.LTD.SamsungWelcome*",                 # Welcome App
    "SAMSUNGELECTRONICSCO.LTD.SamsungSecurity1.2*",             # Samsung Security Tool
    "SAMSUNGELECTRONICSCO.LTD.SamsungScreenRecording*",         # Screen Recorder
    "SAMSUNGELECTRONICSCO.LTD.SamsungQuickSearch*",             # Search App
    "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner*",               # System Cleaner
    "SAMSUNGELECTRONICSCO.LTD.SamsungCloudBluetoothSync*",      # Cloud Sync
    "SAMSUNGELECTRONICSCO.LTD.PCGallery*",                      # Photo Viewer
    "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService*",          # Online Support
    "4AE8B7C2.BOOKING.COMPARTNERAPPSAMSUNGEDITION*"             # Booking.com App
    "Samsung.Free*",                                            # Free (news & media feed)
    "Samsung.Kids*",                                            # Kids (parental control)
    "Samsung.Pass*",                                            # Pass (password manager)
    "Samsung.GlobalGoals*",                                     # Global Goals (charity)
    "Samsung.Internet*",                                        # Internet (browser)
    "Samsung.Email*",                                           # Email (mail client)
    "Samsung.Members*",                                         # Members (community/support)
    "Samsung.Health*",                                          # Health (fitness tracking)
    "Samsung.SmartThings*",                                     # SmartThings (smart home)
    "Samsung.TVPlus*"                                           # TV Plus (free TV service)

)

foreach ($App in $Apps) {
    Write-Host " - Removed: $App" -ForegroundColor Green

    $Installed = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $App }
    foreach ($Install in $Installed) {
        # Remove for all existing users
        Remove-AppxProvisionedPackage -Online -PackageName $Install.PackageName -ErrorAction SilentlyContinue
    }
    # Remove provisioned package (prevents future installs)
    Get-AppxPackage -AllUsers -Name $App | Remove-AppxPackage -ErrorAction SilentlyContinue
}

# Outlook (only if Desktop version installed)
if (Test-Path "C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE") {
    Remove-AppxProvisionedPackage -Online -PackageName (Get-AppxPackage -AllUsers -Name "Microsoft.OutlookForWindows").PackageName -ErrorAction SilentlyContinue
    Get-AppxPackage -AllUsers -Name "Microsoft.OutlookForWindows" | Remove-AppxPackage -ErrorAction SilentlyContinue
    Write-Host " - Removed: Outlook (Metro)" -ForegroundColor Green
}

# REMOVAL - Microsoft Desktop App Installer
#> Silently manages installation and updating of Windows apps, especially those distributed as MSIX or APPX packages.
Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe | Out-Null
# Disable silent installation of third-party apps suggested by Microsoft Store
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value "0"
# Block all content recommendations in Windows (e.g. tips, app suggestions)
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value "0"
# Disable personalized and cloud-driven suggestions (e.g. Start menu recommendations)
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Type DWord -Value "0"
# Prevent reinstall of preloaded OEM/factory apps
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value "0"
# Mark system as never having allowed OEM preinstalled apps (prevents reinstall triggers)
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type String -Value "0"
# Disable OEM-specific apps from auto-installing
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OEMPreInstalledAppsEnabled" -Type DWord -Value "0"
# Turn off Start menu suggestions (e.g. WhatsApp recommendations under "Recommended")
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Type DWord -Value "0"

# Restore Progress Bars
$ProgressPreference = "Continue"                    # Restore Progress Bars
#endregion


#region Windows 10/11 - Applications - Desktop
Write-Host "3.2 Applications - Desktop" -ForegroundColor Green
# 3.2.1 Edge
Write-Host "3.2.1 Microsoft Edge" -ForegroundColor Green
#> Services
Get-Service "edgeupdate" | Stop-Service -ErrorAction SilentlyContinue
Get-Service "edgeupdatem" | Stop-Service -ErrorAction SilentlyContinue
Get-Service "edgeupdate" | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
Get-Service "edgeupdatem" | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
Set-Registry -Path 'HKLM:\SYSTEM\CurrentControlSet\Services' -Name 'edgeupdate' -Remove Path
Set-Registry -Path 'HKLM:\SYSTEM\CurrentControlSet\Services' -Name 'edgeupdatem' -Remove Path
Write-Host "Microsoft Edge - Auto Update Services [DISABLED]" -ForegroundColor Green
#> Scheduled Tasks
Get-Scheduledtask "*edge*" | Disable-ScheduledTask | Out-Null
Write-Host "Microsoft Edge - Auto Start - Scheduled Task [DISABLED]" -ForegroundColor Green
#> Auto Start
Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'AllowPrelaunch' -Value 0 -Type DWord
$paths = @(
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
  "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
)
foreach ($path in $paths) {
    Get-ItemProperty -Path $path |
        Get-Member -MemberType NoteProperty |
        Where-Object { $_.Name -like '*MicrosoftEdge*' } |
        ForEach-Object {
            Remove-ItemProperty -Path $path -Name $_.Name -Force
        }
}
Write-Host "Microsoft Edge - Auto Start - Startup Entries [DISABLED]" -ForegroundColor Green
#> Tracking
Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -Name 'DoNotTrack' -Value 1 -Type DWord
Write-Host "Microsoft Edge - Tracking [DISABLED]" -ForegroundColor Green
#> Addons
Get-WmiObject -Query "SELECT * FROM Win32_Product WHERE Name LIKE '%Microsoft Search in Bing%'" | ForEach-Object { $_.Uninstall() > $null 2>&1 }
Write-Host "Microsoft Edge - Bloat Search Addon [REMOVED]" -ForegroundColor Green

# 3.2.2 OneDrive
Write-Host "3.2.2 One Drive" -ForegroundColor Green
if (Test-OneDriveSyncing) {
    # DisableFileSync (Enable)
    Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -Type DWord -Value 0
    # DisableFileSyncNGSC (Enable)
    Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Type DWord -Value 0  
	Write-Host "3.2.2 Microsoft One Drive Removal [Skipped]" -ForegroundColor Yellow
} else {
    	#> Close OneDrive (if running in background)
		taskkill /f /im OneDrive.exe
		taskkill /f /im FileCoAuth.exe
		#> Official Removal
        # x86
        $OneDriveSetup32 = "$Env:WinDir\System32\OneDriveSetup.exe"
        if (Test-Path $OneDriveSetup32) { Start-Process -FilePath $OneDriveSetup32 -WorkingDirectory "$Env:WinDir\System32" -ArgumentList "/uninstall" | Out-Null }

        # x64
        $OneDriveSetup64 = "$Env:WinDir\SysWOW64\OneDriveSetup.exe"
        if (Test-Path $OneDriveSetup64) { Start-Process -FilePath $OneDriveSetup64 -WorkingDirectory "$Env:WinDir\SysWOW64" -ArgumentList "/uninstall" | Out-Null }
		#> Files Cleanup
		# File Explorer - Navigation Bar
        Set-Registry -Path 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name '(default)' -Type String -Value 'OneDrive'
        Set-Registry -Path 'HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}' -Name 'System.IsPinnedToNameSpaceTree' -Type DWord -Value 0
		# AppData / Local
        $LocalOneDrive = "$env:LOCALAPPDATA\OneDrive"
        if (Test-Path $LocalOneDrive) { Remove-Item -Path $LocalOneDrive -Recurse -Confirm:$false -Force }
        # ProgramData
        $ProgramDataOneDrive = "$env:PROGRAMDATA\Microsoft OneDrive"
        if (Test-Path $ProgramDataOneDrive) { Remove-Item -Path $ProgramDataOneDrive -Recurse -Force | Out-Null }
        # Shortcuts
        $ShortcutUser = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
        if (Test-Path $ShortcutUser) { Remove-Item -Path $ShortcutUser -Force | Out-Null }
        $ShortcutCommon = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"
        if (Test-Path $ShortcutCommon) { Remove-Item -Path $ShortcutCommon -Force | Out-Null }
        # Program Files
        $OneDrivePFx86 = "C:\Program Files (x86)\Microsoft OneDrive"
        if (Test-Path $OneDrivePFx86) { Remove-Item -LiteralPath $OneDrivePFx86 -Recurse -Confirm:$false -Force | Out-Null }
        $OneDrivePF = "C:\Program Files\Microsoft OneDrive"
        if (Test-Path $OneDrivePF) { Remove-Item -LiteralPath $OneDrivePF -Recurse -Confirm:$false -Force | Out-Null }
		#> Scheduled Tasks
		Get-ScheduledTask "*OneDrive*" | Unregister-ScheduledTask -Confirm:$false
		#> Services
		$ODUPdaterService = Get-WmiObject -Class Win32_Service -Filter "Name='OneDrive Updater Service'" | Out-Null
		$ODUpdaterService = Get-WmiObject -Class Win32_Service -Filter "Name='OneDrive Updater Service'" -ErrorAction SilentlyContinue
        if ($ODUpdaterService) { $ODUpdaterService.Delete() | Out-Null }
		#> Registry
        # Remove Previous Accounts/Sync Options
        Set-Registry -Remove Path -Path "HKCU:\Software\Microsoft\OneDrive"
        # Remove previously set One Drive settings
        Set-Registry -Remove Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
        # Remove Right Click Menu Context Options
        Set-Registry -Remove Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\FileSyncHelper"
		# Remove from 'Default' user account
		reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
		reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
		reg unload "hku\Default"
		#########################################
        ### DISABLE ONE DRIVE FROM BEING USED ###
        #########################################
        # DisableFileSync
        Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSync' -Type DWord -Value 0
        # DisableFileSyncNGSC
        Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive' -Name 'DisableFileSyncNGSC' -Type DWord -Value 0  
		Write-Host "3.2.2 Microsoft One Drive [Removed]" -ForegroundColor Yellow
}

## 3.2.3 Internet Explorer
Write-Host "3.2.3 Internet Explorer" -ForegroundColor Green
#> Add-Ons
# Send to One Note
Set-Registry -Remove Path -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}"
Set-Registry -Remove Path -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{2670000A-7350-4f3c-8081-5663EE0C6C49}"
Write-Host "Internet Explorer - Add-On: 'Send to One Note' [REMOVED]" -ForegroundColor Green
# OneNote Linked Notes
Set-Registry -Remove Path -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}"
Set-Registry -Remove Path -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Extensions\{789FE86F-6FC4-46A1-9849-EDE0DB0C95CA}"
Write-Host "Internet Explorer - Add-On: 'OneNote Linked Notes' [REMOVED]" -ForegroundColor Green
# Lync Click to Call
Set-Registry -Remove Value -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Extensions" -Name "{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}"
Set-Registry -Remove Value -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects" -Name "{31D09BA0-12F5-4CCE-BE8A-2923E76605DA}"
Write-Host "Internet Explorer - Add-On: 'Lync Click to Call' [REMOVED]" -ForegroundColor Green
# IE to Edge Browser Helper Object
Set-Registry -Remove Path -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{1FD49718-1D00-4B19-AF5F-070AF6D5D54C}"
$existingTask = Get-ScheduledTask | Where-Object { $_.TaskName -like "Internet Explorer - IEtoEDGE Addon Removal" }
if ($null -eq $existingTask) {
    Get-ChildItem -Path "C:\Program Files (x86)\Microsoft\Edge\Application" -Recurse -Filter "BHO" | Remove-Item -Force -Recurse
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "Get-ChildItem -Path 'C:\Program Files (x86)\Microsoft\Edge\Application' -Recurse -Filter 'BHO' | Remove-Item -Force -Recurse"
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "Internet Explorer - IEtoEDGE Addon Removal" -Description "Removes the Internet Explorer Addon IEtoEDGE.  This will permit the use of Internet Explorer." -Principal $STPrin | Out-Null
}
Write-Host "Internet Explorer - Add-On: 'IE to Edge' [REMOVED]" -ForegroundColor Green

## 3.2.4 One Note
Write-Host "3.2.4 One Note" -ForegroundColor Green
Remove-Item -LiteralPath "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\Send to OneNote.lnk" -ErrorAction "SilentlyContinue" -Force | Out-Null
Set-Registry -Remove Value -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder" -Name "Send to OneNote.lnk"
Write-Host "OneNote - Startup: 'Send to OneNote' [REMOVED]" -ForegroundColor Green

## 3.2.5 Mozilla Firefox
Write-Host "3.2.5 Mozilla Firefox" -ForegroundColor Green
# Scheduled Tasks
Get-ScheduledTask "*Firefox Default*" | Unregister-ScheduledTask -Confirm:$false
Write-Host "Firefox - 'Periodic requests to set as default browser' [DISABLED]" -ForegroundColor Green

## 3.2.6 Teams (Home / Small Business)
Write-Host "3.2.6 Teams (Home / Small Business)" -ForegroundColor Green
Set-Registry -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'TaskbarMn' -Value 0 -Type DWord
Write-Host "Teams (Home / Small Business) - Taskbar Shortcut [REMOVED]" -ForegroundColor Green

## 3.2.7 Teams (Work or School)
Write-Host "3.2.7 Teams (Work or School) - Disabled Auto Start" -ForegroundColor Green
Set-Registry -Remove Value -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "com.squirrel.Teams.Teams"
Set-Registry -Remove Value -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "TeamsMachineInstaller"
Set-Registry -Remove Value -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" -Name "TeamsMachineUninstallerLocalAppData"
Set-Registry -Remove Value -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32" -Name "TeamsMachineUninstallerProgramData"
Write-Host "Teams (Work or School) - Auto Start [DISABLED]" -ForegroundColor Green

## 3.2.8 Windows Suggestions/Tips/Welcome Experience
Write-Host "3.2.8 Windows Suggestions/Tips/Welcome Experience" -ForegroundColor Green
# Source: https://www.elevenforum.com/t/disable-ads-in-windows-11.8004/
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" |
    Get-Member -MemberType NoteProperty |
    Where-Object { $_.Name -like "SubscribedContent*" } |
    ForEach-Object {
        Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name $_.Name -Value 0
    }
Write-Host "Windows Suggestions/Tips/Welcome Experience [DISABLED]" -ForegroundColor Green

## 3.2.9 Sysinternals Installation
Write-Host "3.2.9 Sysinternals" -ForegroundColor Green
Invoke-WebRequest -Uri "https://live.sysinternals.com/Autoruns.exe" -OutFile "C:\Windows\System32\Autoruns.exe"
Invoke-WebRequest -Uri "https://live.sysinternals.com/Autoruns64.exe" -OutFile "C:\Windows\System32\Autoruns64.exe"
Write-Host "Sysinternals - Autoruns / Autoruns64 [INSTALLED]" -ForegroundColor Green
Write-Host "Official Website: https://learn.microsoft.com/en-us/sysinternals/" -ForegroundColor Green

## 3.3.10 Cortana
# Disable
Set-Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Value 0 -Type DWord
# Disable Lock Screen
Set-Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortanaAboveLock" -Value 0 -Type DWord
# Disable Cloud Search
Set-Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCloudSearch" -Value 0 -Type DWord
# Disable Bing Search Integration
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 0 -Type DWord
# Disable Cortana Consent UI
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 0 -Type DWord
# Disable Web Search Suggestions (taskbar)
Set-Registry -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1 -Type DWord
Get-AppxPackage -AllUsers Microsoft.549981C3F5F10 | Remove-AppxPackage | Out-Null
Write-Host "3.3.10 Explorer: Cortana [DISABLED]" -ForegroundColor Green

## 3.4.11 Dynamic Lighting
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Lighting" -Name "AmbientLightingEnabled" -Value "0"
Write-Host "3.4.11 Microsoft Dynamic Lighting (RGB Fix) [Disabled]" -ForegroundColor Green
#endregion

#endregion


<#############################################################################################################################>
#region 4.0 - Services and Scheduled Tasks
Write-Host "`n`n4.0 Services and Scheduled Tasks" -ForegroundColor Green
## Services
Write-Host "4.1 Services" -ForegroundColor Green
#> Disable
$services = @(
    "MapsBroker",						# Bing Downloaded Maps Manager
    "autotimesvc",						# Celluar Time
    "cbdhsvc_*",                        # Clipboard History Service
    "WpcMonSvc",						# Parental Controls
    "PhoneSvc",							# Phone Service
    "WPDBusEnum",						# Portable Device Enumerator Service
    "PcaSvc",							# Program Compatibility Assistant Service
    "RemoteRegistry",					# Remote Registry
    "RetailDemo",						# Retail Demo
    "TapiSrv",                          # Telephony
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
    try {
        $svc = Get-Service -Name $service -ErrorAction Stop
        $serviceName = $svc.DisplayName
        Stop-Service -Name $service -ErrorAction SilentlyContinue
        Set-Service -Name $service -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host " - Service: $serviceName [DISABLED]" -ForegroundColor Green
    } catch {
        Write-Host " - Service: $service [NOT FOUND]" -ForegroundColor Yellow
    }
}
#> Disable - Superfetch/Prefetch Disable (if running SSD)
$disk = Get-PhysicalDisk | Where-Object { $_.DeviceID -eq (Get-Disk -Number (Get-Partition -DriveLetter C).DiskNumber).Number }
if ($disk.MediaType -eq 'SSD') {
    Stop-Service -Name SysMain -Force
    Set-Service -Name SysMain -StartupType Disabled
    Write-Host " - Service: Superfetch/Prefetch [DISABLED]" -ForegroundColor Green
} else {
    Write-Host " - Service: Superfetch/Prefetch [UNMODIFIED (HDD Detected)]" -ForegroundColor Green
}
#> Disable - DiagTrack/dmwappushservice
$intuneInstalled = Get-Service -Name "IntuneManagementExtension" -ErrorAction SilentlyContinue
if (!($intuneInstalled)) {
    # DiagTrack (Telemetry + Timeline)
    Stop-Service DiagTrack -Force -ErrorAction SilentlyContinue
    Set-Service DiagTrack -StartupType Disabled
    Write-Host " - Service: DiagTrack (Telemetry + Timeline) [DISABLED]" -ForegroundColor Green

    # dmwappushservice (Push-based Clipboard Sync)
    Stop-Service dmwappushservice -Force -ErrorAction SilentlyContinue
    Set-Service dmwappushservice -StartupType Disabled
    Write-Host " - Service: dmwappushservice (Push-based Clipboard Sync) [DISABLED]" -ForegroundColor Green
}
#> Delete - Windows Media Player Network Share
if (Get-Service -Name 'WMPNetworkSvc' -ErrorAction SilentlyContinue) {
    sc.exe delete WMPNetworkSvc
    Write-Host " - Service: Windows Media Player Network Share [DELETED]" -Foregroundcolor Green
}
#> Manual - Bluetooth
$services = @(
    "BTAGService",  # Bluetooth
    "bthserv"       # Bluetooth
)
foreach ($service in $services) {
    $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
    if ($null -ne $svc) {
        $svc | Stop-Service -ErrorAction SilentlyContinue
        $svc | Set-Service -StartupType Manual -ErrorAction SilentlyContinue
        Write-Host " - Service: $($svc.DisplayName) [Set to Manual]" -ForegroundColor Green
    }
}


## Scheduled Tasks
Write-Host "4.2 Scheduled Tasks" -ForegroundColor Green
# Tasks - Intune Related
$removedCount = 0
if (!($intuneInstalled)) {
    $Tasks = @(
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater",
        "\Microsoft\Windows\Application Experience\StartupAppTask",
        "\Microsoft\Windows\Autochk\Proxy",
        "\Microsoft\Windows\Customer Experience Improvement Program\BthSQM",
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask",
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
    )

    foreach ($task in $Tasks) {
        try {
            $taskName = ($task.Split('\')[-1])
            $taskPath = ($task -replace "\\$taskName$", "")
            Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue | Out-Null
            $removedCount++
            Write-Host " - Task: $task [DISABLED]" -ForegroundColor Green
        } catch {
            Write-Host " - Task: $task [NOT FOUND]" -ForegroundColor Yellow
        }
    }
}
# Tasks - General/All Systems
$taskData = @(
    @{ TaskName = "Proxy"; TaskPath = "\Microsoft\Windows\Autochk\"; DisplayName = "Proxy Task" },
    @{ TaskName = "SmartScreenSpecific"; TaskPath = "\Microsoft\Windows\AppID\"; DisplayName = "SmartScreen Specific Task" },
    @{ TaskName = "Microsoft Compatibility Appraiser"; TaskPath = "\Microsoft\Windows\Application Experience\"; DisplayName = "Microsoft Compatibility Appraiser Task" },
    @{ TaskName = "ProgramDataUpdater"; TaskPath = "\Microsoft\Windows\Application Experience\"; DisplayName = "Program Data Updater Task" },
    @{ TaskName = "AitAgent"; TaskPath = "\Microsoft\Windows\Application Experience\"; DisplayName = "Application Experience AIT Agent" },
    @{ TaskName = "Consolidator"; TaskPath = "\Microsoft\Windows\Customer Experience Improvement Program\"; DisplayName = "Consolidator Task" },
    @{ TaskName = "KernelCeipTask"; TaskPath = "\Microsoft\Windows\Customer Experience Improvement Program\"; DisplayName = "Kernel CEIP Task" },
    @{ TaskName = "UsbCeip"; TaskPath = "\Microsoft\Windows\Customer Experience Improvement Program\"; DisplayName = "USB CEIP Task" },
    @{ TaskName = "Microsoft-Windows-DiskDiagnosticDataCollector"; TaskPath = "\Microsoft\Windows\DiskDiagnostic\"; DisplayName = "Disk Diagnostic Data Collector Task" },
    @{ TaskName = "Microsoft-Windows-DiskDiagnosticResolver"; TaskPath = "\Microsoft\Windows\DiskDiagnostic\"; DisplayName = "Disk Diagnostic Resolver Task" },
    @{ TaskName = "GatherNetworkInfo"; TaskPath = "\Microsoft\Windows\NetTrace\"; DisplayName = "Gather Network Info Task" },
    @{ TaskName = "QueueReporting"; TaskPath = "\Microsoft\Windows\Windows Error Reporting\"; DisplayName = "Queue Reporting Task" },
    @{ TaskName = "UpdateLibrary"; TaskPath = "\Microsoft\Windows\Windows Media Sharing\"; DisplayName = "Update Library Task" },
    @{ TaskName = "WinSAT"; TaskPath = "\Microsoft\Windows\Maintenance\"; DisplayName = "Windows System Assessment Tool" },
    @{ TaskName = "MapsToastTask"; TaskPath = "\Microsoft\Windows\Maps\"; DisplayName = "Maps Toast Task" },
    @{ TaskName = "MapsUpdateTask"; TaskPath = "\Microsoft\Windows\Maps\"; DisplayName = "Maps Update Task" },
    @{ TaskName = "AnalyzeSystem"; TaskPath = "\Microsoft\Windows\Power Efficiency Diagnostics\"; DisplayName = "Power Efficiency Diagnostics" }
)
foreach ($taskInfo in $taskData) {
    $taskName = $taskInfo.TaskName
    $taskPath = $taskInfo.TaskPath
    $displayName = $taskInfo.DisplayName
    try {
        if (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Host " - Task: '$displayName' [REMOVED]" -ForegroundColor Green
            $removedCount++
        }
    } catch {
        Write-Host " - Task: '$displayName' [FAILED or NOT FOUND]" -ForegroundColor Yellow
    }
}
if ($removedCount -eq 0) {
    Write-Host " - Task: All removed previously!" -ForegroundColor Yellow
}
#endregion

<#############################################################################################################################>
#region 5.0 - Quality of Life
Write-Host "`n`n5.0 Quality of Life" -ForegroundColor Green

<###################################### EXPLORER TWEAKS (Start) ######################################>
# Restore 'Windows 10' Right Click Context Menu
if((Test-Path -LiteralPath "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32") -ne $true) {New-Item "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Force | Out-Null}
Set-Registry -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -Type String -Value ""
Write-Host "Explorer: Windows 10 - Right Click Context Menu [RESTORED]" -ForegroundColor Green

# Right Click Context Menu - Add "Open with Powershell 5.1 (Admin)"
# Remove old variant registry path (prevent duplicate entry)
Set-Registry -Remove Path -Path "HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShellAsAdmin"
Set-Registry -Remove Path -Path "HKLM:\SOFTWARE\Classes\Directory\shell\PowerShellAsAdmin"
Set-Registry -Remove Path -Path "HKLM:\SOFTWARE\Classes\Drive\shell\PowerShellAsAdmin"
Set-Registry -Remove Path -Path "HKLM:\SOFTWARE\Classes\LibraryFolder\Background\shell\PowerShellAsAdmin"
# Add
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell5AsAdmin' -Name '(default)' -Value 'Open with PowerShell 5 (Admin)' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell5AsAdmin' -Name 'Extended' -Remove Value
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell5AsAdmin' -Name 'HasLUAShield' -Value '' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell5AsAdmin' -Name 'Icon' -Value 'powershell.exe' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell5AsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell5AsAdmin' -Name '(default)' -Value 'Open with PowerShell 5 (Admin)' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell5AsAdmin' -Name 'Extended' -Remove Value
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell5AsAdmin' -Name 'HasLUAShield' -Value '' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell5AsAdmin' -Name 'Icon' -Value 'powershell.exe' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell5AsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell5AsAdmin' -Name '(default)' -Value 'Open with PowerShell 5 (Admin)' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell5AsAdmin' -Name 'Extended' -Remove Value
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell5AsAdmin' -Name 'HasLUAShield' -Value '' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell5AsAdmin' -Name 'Icon' -Value 'powershell.exe' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell5AsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs powershell.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\"' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLinkedConnections' -Value 1 -Type DWord
Write-Host "Explorer: 'Open with PowerShell 5.1 (Admin)' - Right Click Context Menu [ADDED]" -ForegroundColor Green

# Right Click Context Menu - Add "Open with Powershell 7 (Admin)"
$PS7InstallerURL = "https://github.com/PowerShell/PowerShell/releases/download/v7.5.2/PowerShell-7.5.2-win-x64.msi"
if ($url -match "download/v([^/]+)") { $PS7_version = $matches[1] }

# Install
if (-not (Test-Path "C:\Program Files\PowerShell\7\pwsh.exe")) {
    Write-Host "Explorer: PowerShell 7 [DOWNLOADING]" -ForegroundColor Yellow
    New-Item -Path "C:\PSTemp" -ItemType Directory | Out-Null
    Invoke-WebRequest -Uri $PS7InstallerURL -OutFile "C:\PSTemp\PowerShell-7.msi"
    Start-Process -FilePath msiexec -ArgumentList "/i `"C:\PSTemp\PowerShell-7.msi`" /qn" -Wait
    Remove-Item -Path "C:\PSTemp" -Recurse -Force | Out-Null
    Write-Host "Explorer: PowerShell 7 [INSTALLED]" -ForegroundColor Green
}

# Update
if ((& "C:\Program Files\PowerShell\7\pwsh.exe" -NoLogo -NoProfile -Command '$PSVersionTable.PSVersion.ToString()') -lt $PS7_version) {
    Write-Host "Explorer: PowerShell 7 [OUTDATED] → [UPDATING]" -ForegroundColor Yellow
    New-Item -Path "C:\PSTemp" -ItemType Directory -Force | Out-Null
    Invoke-WebRequest -Uri $PS7InstallerURL -OutFile "C:\PSTemp\PowerShell-7.msi"
    Start-Process -FilePath msiexec -ArgumentList "/i `"C:\PSTemp\PowerShell-7.msi`" /qn" -Wait
    Remove-Item -Path "C:\PSTemp" -Recurse -Force | Out-Null
    Write-Host "Explorer: PowerShell 7 [UPDATED]" -ForegroundColor Green
} else {
    Write-Host "Explorer: PowerShell 7 [UP-TO-DATE]" -ForegroundColor Green
}

# Add
Set-Registry -Remove Path -Path "HKLM:\SOFTWARE\Classes\LibraryFolder\Background\shell\PowerShell7AsAdmin"
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin' -Name '(default)' -Value 'Open with PowerShell 7 (Admin)'
Set-Registry -Remove Value -Path 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin' -Name 'Extended'
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin' -Name 'HasLUAShield' -Value ''
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin' -Name 'Icon' -Value 'powershell.exe'
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\Background\shell\PowerShell7AsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs pwsh.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\""'
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin' -Name '(default)' -Value 'Open with PowerShell 7 (Admin)'
Set-Registry -Remove Value -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin' -Name 'Extended'
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin' -Name 'HasLUAShield' -Value ''
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin' -Name 'Icon' -Value 'pwsh.exe'
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Directory\shell\PowerShell7AsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs pwsh.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\""'
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin' -Name '(default)' -Value 'Open with PowerShell 7 (Admin)'
Set-Registry -Remove Value -Path 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin' -Name 'Extended'
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin' -Name 'HasLUAShield' -Value ''
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin' -Name 'Icon' -Value 'pwsh.exe'
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Drive\shell\PowerShell7AsAdmin\command' -Name '(default)' -Value 'powershell -WindowStyle Hidden -NoProfile -Command "Start-Process -Verb RunAs pwsh.exe -ArgumentList \"-NoExit -Command Push-Location \\\"\"%V/\\\"\"\""'
Write-Host "Explorer: 'Open with PowerShell 7 (Admin)' - Right Click Context Menu [ADDED]" -ForegroundColor Green

# Right Click Context Menu - Add "Run as Different User"
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'Extended' -Value $null -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\exefile\shell\runasuser' -Name 'Icon' -Value 'imageres.dll,-5203' -Type String
Write-Host "Explorer: 'Run as different user' - Right Click Context Menu [ADDED]" -ForegroundColor Green

# Right Click Context Menu - Add "Copy as Path"
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name '(default)' -Value 'Copy &as path' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'InvokeCommandOnSelection' -Value 1 -Type DWord
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'VerbHandler' -Value '{f3d06e7c-1e45-4a26-847e-f9fcdee59be0}' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'VerbName' -Value 'copyaspath' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Classes\Allfilesystemobjects\shell\windows.copyaspath' -Name 'Icon' -Value 'imageres.dll,-5302' -Type String
Write-Host "Explorer: 'Copy as Path' - Right Click Context Menu [ADDED]" -ForegroundColor Green

# Right Click Context Menu - Remove "Add to Favorites" (2025-06-12 - Needs to stay as New-ItemProperty)
if((Test-Path -LiteralPath "HKLM:\SOFTWARE\Classes\*\shell\pintohomefile") -ne $true) {New-Item "HKLM:\SOFTWARE\Classes\*\shell\pintohomefile" -Force | Out-Null}
New-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Classes\*\shell\pintohomefile' -Name 'ProgrammaticAccessOnly' -Value "" -PropertyType String -Force | Out-Null
Write-Host "Explorer: 'Add to Favorites' - Right Click Context Menu [REMOVED]" -ForegroundColor Green

# Right Click Context Menu - Add "Convert to JPG"
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
    Write-Host "Explorer: File Convert .JFIF to .JPG - Right Click Context Menu [ADDED]" -ForegroundColor Green
} ELSE {
    Write-Host "Explorer: File Convert .JFIF to .JPG - Right Click Context Menu [ADDED (Previously)]" -ForegroundColor Green
}

# Right Click Context Menu "Add Watermark"
$scriptDir = "C:\ProgramData\AV\Watermark"
if (-not (Test-Path -Path $scriptDir)) {
    New-Item -Path $scriptDir -ItemType Directory -Force
}

$scriptContent = @'
Add-Type -AssemblyName System.Drawing

function Resize-AndAddWatermark {
    param (
        [string]$imagePath
    )

    # Load image
    $image = [System.Drawing.Image]::FromFile($imagePath)

    # Resize image
    $newWidth = 800
    $newHeight = 600
    $resizedImage = New-Object System.Drawing.Bitmap $image, $newWidth, $newHeight

    # Create graphics object
    $graphics = [System.Drawing.Graphics]::FromImage($resizedImage)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([System.Drawing.Color]::White)

    # Draw the image onto the resized image
    $graphics.DrawImage($image, 0, 0, $newWidth, $newHeight)

    # Set watermark text properties
    $font = New-Object System.Drawing.Font("Arial", 120, [System.Drawing.FontStyle]::Bold)
    $brush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(50, 255, 255, 255)) # Semi-transparent white

    # Draw main centered watermark text
    $mainText = "PREVIEW"
    $textWidth = $graphics.MeasureString($mainText, $font).Width
    $textHeight = $graphics.MeasureString($mainText, $font).Height
    $centerX = ($newWidth - $textWidth) / 2
    $centerY = ($newHeight - $textHeight) / 2
    $graphics.DrawString($mainText, $font, $brush, $centerX, $centerY)

    # Tiled and distorted watermark text
    $tileFont = New-Object System.Drawing.Font("Arial", 50, [System.Drawing.FontStyle]::Bold)
    $tileBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30, 255, 255, 255)) # Lighter transparency

    $tileWidth = 200
    $tileHeight = 100
    for ($y = 0; $y -lt $newHeight; $y += $tileHeight) {
        for ($x = 0; $x -lt $newWidth; $x += $tileWidth) {
            # Apply random rotation and scaling
            $angle = (Get-Random -Minimum -15 -Maximum 15)
            $scale = (Get-Random -Minimum 0.8 -Maximum 1.2)

            # Create a transformation matrix
            $matrix = New-Object System.Drawing.Drawing2D.Matrix
            $matrix.RotateAt($angle, [System.Drawing.PointF]::new($x + $tileWidth / 2, $y + $tileHeight / 2))
            $matrix.Scale($scale, $scale)

            # Apply the transformation
            $graphics.Transform = $matrix
            $graphics.DrawString($mainText, $tileFont, $tileBrush, $x, $y)
            $graphics.ResetTransform()
        }
    }

    # Save the output image
    $directory = [System.IO.Path]::GetDirectoryName($imagePath)
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($imagePath)
    $outputPath = Join-Path -Path $directory -ChildPath ("$fileName`_resized.jpg")

    $counter = 1
    while (Test-Path $outputPath) {
        $outputPath = Join-Path -Path $directory -ChildPath ("$fileName`_resized($counter).jpg")
        $counter++
    }

    $resizedImage.Save($outputPath, [System.Drawing.Imaging.ImageFormat]::Jpeg)

    # Clean up
    $graphics.Dispose()
    $resizedImage.Dispose()
    $image.Dispose()
}

Resize-AndAddWatermark -imagePath $args[0]
'@

$scriptPath = Join-Path -Path $scriptDir -ChildPath "ResizeAndAddWatermark.ps1"
$scriptContent | Out-File -FilePath $scriptPath -Force

$regPathJPG = "HKCU:\Software\Classes\SystemFileAssociations\.jpg\shell\AddWatermark"
$regPathPNG = "HKCU:\Software\Classes\SystemFileAssociations\.png\shell\AddWatermark"

$regKeys = @($regPathJPG, $regPathPNG)

foreach ($key in $regKeys) {
    if (-not (Test-Path $key)) {
        New-Item -Path $key -Force
    }

    Set-ItemProperty -Path $key -Name "(Default)" -Value "Add Watermark"

    $commandKeyPath = "$key\command"
    if (-not (Test-Path $commandKeyPath)) {
        New-Item -Path $commandKeyPath -Force
    }

    Set-ItemProperty -Path $commandKeyPath -Name "(Default)" -Value "powershell.exe -ExecutionPolicy Bypass -File `"$scriptPath`" `"%1`""
    Set-ItemProperty -Path $key -Name "Icon" -Value "shell32.dll,43"
}
Write-Host "Explorer: .JPG/.PNG 'Add Watermark' - Right Click Context Menu [ADDED]" -ForegroundColor Green

Set-Registry -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Value 1 -Type DWord
Write-Host "Explorer: Set Explorer to open with 'This PC' instead of 'Most Recent'" -ForegroundColor Green

Set-Registry -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowDriveLettersFirst" -Type DWord -Value 4
Write-Host "Explorer: Drive letters PRE drive label [Example: '(C:) Windows vs. Windows (C:)]'" -ForegroundColor Green

Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -Type DWord
Write-Host "Explorer: Display of Known File Extensions [ENABLED]" -ForegroundColor Green

# Gallery - Source: https://www.elevenforum.com/t/add-or-remove-gallery-in-file-explorer-navigation-pane-in-windows-11.14178/
Set-Registry -Path "HKCU:\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord
Write-Host "Explorer: 'Gallery' Shorcut [REMOVED]" -ForegroundColor Green

# Windows 'Get most of out this device' Suggestions
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Force | Out-Null
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0 -Type DWord
Write-Host "Explorer: 'Getting most out of this device' [DISABLED]" -ForegroundColor Green

# Source: https://www.elevenforum.com/t/enable-or-disable-store-activity-history-on-device-in-windows-11.7812/ #Note: Potentially needed for InTune
Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Value 0 -Type DWord
Write-Host "Explorer: Activity Log [DISABLED]" -ForegroundColor Green

# Tailored Experience
Set-Registry -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Value 1 -Type DWord
Write-Host "Explorer: Tailored Experience [DISABLED]" -ForegroundColor Green

# Personalized Ads
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Force | Out-Null
Set-Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Value 1 -Type DWord
Write-Host "Explorer: Personalized Ads [DISABLED]" -ForegroundColor Green

# Feedback - Source: https://www.makeuseof.com/windows-disable-feedback-notifications/
Set-Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Value 1 -Type DWord
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 -Type DWord
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value 0 -Type DWord
Write-Host "Explorer: Feedback Notifications [DISABLED]" -ForegroundColor Green

Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableSnapBar" -Type DWord -Value 0
Write-Host "Explorer: Snap Layout [DISABLED]" -ForegroundColor Green

Set-Registry -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -Name 'ShowFrequent' -Value 0 -Type DWord
Write-Host "Explorer: 'Recent Folders' in Quick Access [DISABLED]" -ForegroundColor Green

# Remove Widgets (Reinstall Source: https://apps.microsoft.com/detail/windows-web-experience-pack/9MSSGKG348SP?hl=en-us&gl=US)
winget uninstall --accept-source-agreements "Windows web experience pack" | Out-Null
Set-Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Type DWord -Value 0
Write-Host "Explorer: Widgets [REMOVED]" -ForegroundColor Green

Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'DisableLogonBackgroundImage' -Type DWord -Value 1
Write-Host "Explorer: Background on Login Screen [DISABLED]" -ForegroundColor Green

# Source: https://www.kapilarya.com/disable-tips-and-suggestions-notifications-in-windows-11
Set-Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableSoftLanding" -Type DWord -Value 1
Write-Host "Explorer: Tips [DISABLED]" -ForegroundColor Green

# Source: https://documentation.n-able.com/N-central/userguide/Content/Automation/Policies/Diagnostics/pol_UACEnabled_Check.htm
Set-Registry -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type DWord
Write-Host "Explorer: User Access Control - Prompt for Admins [DISABLED]" -ForegroundColor Green

Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name "PromptOnSecureDesktop" -Value 0 -Type DWord
Write-Host "Explorer: User Access Control - Desktop Dimming [DISABLED]" -ForegroundColor Green

Set-Registry -Path "HKCU:\Control Panel\Desktop" -Name "AnimateMinimize" -Value "0" -Type String
Set-Registry -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "0" -Type String
Set-Registry -Path "HKCU:\Control Panel\Desktop" -Name "AnimateWindows" -Value "0" -Type String
Write-Host "Explorer: Animations (Minimize/Maximize) [DISABLED]" -ForegroundColor Green

# Settings > Accessibility > Visual Effects > Transparency Effects
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value "0" -Type DWord
Write-Host "Explorer: Transparency [DISABLED]" -ForegroundColor Green

# Co-Pilot
Set-Registry -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 0 -Type DWord
# Task Bar Removal
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0 -Type DWord
# Right Click Menu "Ask Co-Pilot"
Set-Registry -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked' -Name '{CB3B0003-8088-4EDE-8769-8B354AB2FF8C}' -Value '' -Type String
Write-Host "Explorer: Microsoft Co-Pilot SHORTCUT [REMOVED]" -ForegroundColor Green
<###################################### EXPLORER TWEAKS (End) ######################################>



<###################################### START MENU TWEAKS (Start) ######################################>
if ((Get-WMIObject win32_operatingsystem) | Where-Object { $_.Name -like "Microsoft Windows 11*" }) {
    #Source: https://vhorizon.co.uk/windows-11-start-menu-layout-group-policy/
    Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 0 -Type DWord
	Write-Host "Start Menu: Alignment - Left" -ForegroundColor Green
    Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Value 1 -Type DWord
    Write-Host "Start Menu: Reduced 'Recommended Apps' [UPDATE]" -ForegroundColor Green
}

Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0 -Type DWord
Write-host "Start Menu: 'Task View' Button [HIDDEN]" -ForegroundColor Green

Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "SearchBoxTaskbarMode" -Value 0 -Type DWord
Write-host "Start Menu: 'Search' Button [HIDDEN]" -ForegroundColor Green

Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarDa" -Value 0 -Type DWord
Write-Host "Start Menu: Weather Widget [HIDDEN]" -ForegroundColor Green

# Start Menu - Disable Metro app suggestions.
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value "0"
Write-Host "Start Menu: Metro App Suggestions [DISABLED]" -ForegroundColor Green

Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value 0 -Type DWord
Write-Host "Start Menu: Animations - Icons [DISABLED]" -ForegroundColor Green

Set-Registry -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value 1 -Type String
Write-Host "Start Menu: Animations - Appear/Load Time [REDUCED]" -ForegroundColor Green

# Add 'Devices and Printers' to Start Menu
$ShortcutPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("CommonPrograms"), "Devices & Printers.lnk")
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "shell:::{A8A91A66-3A7D-4424-8D24-04E180695C7A}"
$Shortcut.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WshShell) | Out-Null
Write-Host "Start Menu: 'Devices & Printers' [ADDED]" -ForegroundColor Green

# Add 'Devices and Printers (Drivers)' to Start Menu
$ShortcutPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("CommonPrograms"), "Devices & Printers (Drivers).lnk")
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "C:\Windows\System32\rundll32.exe"
$Shortcut.Arguments = "printui.dll,PrintUIEntry /s"
$Shortcut.IconLocation = "C:\Windows\System32\imageres.dll,38"
$Shortcut.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WshShell) | Out-Null
Write-Host "Start Menu: 'Devices & Printers (Drivers)' [ADDED]" -ForegroundColor Green

# Add 'Devices and Printers (Add Network Printer)' to Start Menu
$ShortcutPath = [System.IO.Path]::Combine([System.Environment]::GetFolderPath("CommonPrograms"), "Devices & Printers (Add Network).lnk")
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = "C:\Windows\System32\rundll32.exe"
$Shortcut.Arguments = "printui.dll,PrintUIEntry /il"
$Shortcut.IconLocation = "C:\Windows\System32\imageres.dll,39"
$Shortcut.Save()
[System.Runtime.Interopservices.Marshal]::ReleaseComObject($WshShell) | Out-Null
Write-Host "Start Menu: 'Devices & Printers (Add Network)' [ADDED]" -ForegroundColor Green

<###################################### START MENU TWEAKS (End) ######################################>



<###################################### NETWORK TWEAKS (Start) ######################################>
Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object {
    Disable-NetAdapterPowerManagement -Name $_.Name -DeviceSleepOnDisconnect -NoRestart | Out-Null
}
Write-Host "Network: Ethernet/Wireless Power Saving Settings [DISABLED]" -ForegroundColor Green

# Source: https://www.majorgeeks.com/content/page/irpstacksize.html (Default 15-20 connections, increased to 50)
Set-Registry -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'IRPStackSize' -Value 48 -Type DWord
Write-Host "Network: Increased Performance for 'I/O Request Packet Stack Size" -ForegroundColor Green

Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile' -Name 'NetworkThrottlingIndex' -Value -1 -Type DWord
Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Psched' -Name 'NonBestEffortLimit' -Value 0 -Type DWord
Write-Host "Network: Throttling Index [DISABLED]" -ForegroundColor Green

netsh int tcp set global autotuninglevel=disabled
Write-Host "Network: TCP Auto-Tuning [DISABLED]" -ForegroundColor Green

netsh int tcp set global rss=enabled
Write-Host "Network: Receive-Side Scaling (RSS) [ENABLED]" -ForegroundColor Green

netsh int tcp set global dca=enabled
Write-Host "Network: Direct Cache Access (DCA) [ENABLED]" -ForegroundColor Green

netsh int tcp set global ecncapability=disabled
Write-Host "Network: Explicit Congestion Notification (ECN) [DISABLED]" -ForegroundColor Green

netsh int tcp set global netdma=disabled
Write-Host "Network: NetDMA [DISABLED]" -ForegroundColor Green

netsh int tcp set supplemental template=internet congestionprovider=ctcp
Write-Host "Network: TCP Congestion Provider set to Compound TCP (CTCP)" -ForegroundColor Green
<###################################### NETWORK TWEAKS (End) ######################################>



<###################################### WINDOWS TWEAKS (Start) ######################################>
# Disable 'High Precision Event Timer' to prevent input lag/delays
bcdedit /deletevalue useplatformclock
bcdedit /set useplatformtick yes
bcdedit /set disabledynamictick yes
Write-Host "Windows: Disabled 'High Precision Event Timer' - Formerly Multimedia Timer" -ForegroundColor Green

Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'GPU Priority' -Value 7 -Type DWord
Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Priority' -Value 5 -Type DWord
Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games' -Name 'Scheduling Category' -Value 'High' -Type String
Write-Host "Windows: Updating 'MMCSS' to prioritize games with higher system resources" -ForegroundColor Green

Set-Registry -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Value 0 -Type DWord
Write-Host "Windows: Disabled Fast Startup - Restored 'Fresh' Reboot" -ForegroundColor Green

Set-Registry -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'ClearPageFileAtShutdown' -Value 1 -Type DWord
Write-Host "Windows: Paging File - Cleared at Shutdown" -ForegroundColor Green

# Source: https://www.thewindowsclub.com/disable-windows-10-startup-delay-startupdelayinmsec (Default=10ms)
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Value 5 -Type DWord
Write-Host "Windows: Reduced Startup Delay" -ForegroundColor Green

# MarkC's Mouse Acceleration Fix (DPI 100% Scale - Default)
# Source: http://donewmouseaccel.blogspot.com/
<# Disable 'Enhance pointer precision' #>
Set-Registry -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseSpeed' -Value 0 -Type String
Set-Registry -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold1' -Value 0 -Type String
Set-Registry -Path 'HKCU:\Control Panel\Mouse' -Name 'MouseThreshold2' -Value 0 -Type String
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

Set-Registry -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications' -Name 'ToastEnabled' -Value 0 -Type DWord
Write-Host "Windows: Toast Notifications [DISABLED]" -ForegroundColor Green

Set-Registry -Path 'HKCU:\Control Panel\Accessibility\StickyKeys' -Name 'Flags' -Value '506' -Type String
Write-Host "Windows: Sticky Keys [DISABLED]" -ForegroundColor Green

Set-Registry -Path 'HKCU:\Control Panel\Accessibility\ToggleKeys' -Name 'Flags' -Value '58' -Type String
Write-Host "Windows: Filter Keys [DISABLED]" -ForegroundColor Green

Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat' -Name 'DisableUAR' -Value 1 -Type DWord
Write-Host "Windows: Troubleshooting 'Steps Recorder' [DISABLED]" -ForegroundColor Green

Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0 -Type DWord
Set-Registry -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0 -Type DWord
Write-Host "Windows: Game Bar [DISABLED]" -ForegroundColor Green

# Smart Screening
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value "0" -Type DWord
Set-Registry -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -Value "0" -Type DWord
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value "Off" -Type String
Write-Host "Windows: App Smart Screening [DISABLED]" -ForegroundColor Green

# Remote Desktop
Set-Registry -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 0 -Type DWord
if (-not (Get-NetFirewallRule -DisplayName "Remote Desktop - TCP (3389)" -ErrorAction SilentlyContinue)) {
    netsh advfirewall firewall add rule name="Remote Desktop - TCP (3389)" dir=in action=allow protocol=TCP localport=3389 profile=domain,private
}
Write-Host "Windows: Remote Desktop [ENABLED]" -ForegroundColor Green

# Lockscreen rotating pictures
Set-Registry -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'RotatingLockScreenEnabled' -Value 0 -Type DWord
Set-Registry -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' -Name 'RotatingLockScreenOverlayEnabled' -Value 0 -Type DWord
Write-Host "Windows: Lockscreen rotating pictures [DISABLED]" -ForegroundColor Green

Set-Registry -Path 'HKCU:\Control Panel\Desktop' -Name 'ForegroundLockTimeout' -Value 0 -Type DWord
Set-Registry -Path 'HKCU:\Control Panel\Desktop' -Name 'HungAppTimeout' -Value '400' -Type String
Set-Registry -Path 'HKCU:\Control Panel\Desktop' -Name 'WaitToKillAppTimeout' -Value '500' -Type String
Set-Registry -Path 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name 'WaitToKillServiceTimeout' -Value '500' -Type String
Write-Host "Windows: Faster Shutdown [ENABLED]" -ForegroundColor Green

# 'Microsoft from getting to know you'
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 -Type DWord
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 0 -Type DWord
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 0 -Type DWord
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 -Type DWord
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" -Name "Enabled" -Value 0 -Type DWord
Set-Registry -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "HistoryViewEnabled" -Value 0 -Type DWord
Write-Host "Windows: 'Microsoft from getting to know you' [DISABLED]" -ForegroundColor Green

# Split Service Host Threshold for increased reliablity
# Source: https://www.tenforums.com/tutorials/94628-change-split-threshold-svchost-exe-windows-10-a.html
$RamInKB = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
$RamInKB = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
if ($RamInKB -ge 16000000) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Value $RamInKB -Force
    Write-Host "Windows: Reduced Service Host Threshold [UPDATED]" -ForegroundColor Green
} else {
    Write-Host "Windows: Reduced Service Host Threshold (Ram <16GB) [SKIPPED]" -ForegroundColor Yellow
}

# Windows Update Delivery Optimization
# Source: https://www.elevenforum.com/t/turn-on-or-off-windows-update-delivery-optimization-in-windows-11.3136
Set-Registry -Path 'Registry::\HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' -Name 'DownloadMode' -Value 0 -Type DWord
Write-Host "Windows: Update Delivery Optimization - Direct Download [UPDATED]" -ForegroundColor Green

# Windows > Display 'Ease cursor Movement between displays'
Set-Registry -Path 'HKCU:\Control Panel\Cursors' -Name 'CursorDeadzoneJumpingSetting' -Value 0 -Type DWord
Write-Host "Windows: 'Ease cursor Movement between displays' [DISABLED]" -ForegroundColor Green

# Windows Background (Spotlight) - Remove "Learn About This Background"
Set-Registry -Remove Path -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{2cc5ca98-6485-489a-920e-b3e88a6ccce3}"
Set-Registry -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" -Value 1 -Type DWord
Write-Host "Windows: Background (Spotlight) - 'Learn About This Background' [REMOVED]" -ForegroundColor Green

# Source: https://www.tomshardware.com/how-to/disable-vbs-windows-11
#> Disable VBS & Device Guard
Set-Registry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Value 0 -Type DWord
Set-Registry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "RequirePlatformSecurityFeatures" -Value 0 -Type DWord
#> Disable Credential Guard
Set-Registry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 0 -Type DWord
Set-Registry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0 -Type DWord
Write-Host "Windows: Virtualization-Based Security [DISABLED]" -ForegroundColor Green

Set-Registry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1 -Type DWord
Write-Host "Windows: Power Throttling [DISABLED]" -ForegroundColor Green

Set-Registry -Remove Value -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth"
Set-Registry -Remove Value -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" -Name "SecurityHealth"
Write-Host "Windows: Security System Tray Icon [HIDDEN]" -ForegroundColor Green

$VMsRunning = Get-VM | Where-Object { $_.State -eq 'Running' }
if ($VMsRunning -or (Test-Path "C:\Program Files\Docker\")) {
    Write-Host "Windows: Hyper-V [Skipped]" -ForegroundColor Yellow
} else {
    Set-Registry -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -Type DWord
    Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -NoRestart | Out-Null
    bcdedit /set hypervisorlaunchtype off
    Write-Host "Windows: Hyper-V [DISABLED]" -ForegroundColor Green
}
<###################################### WINDOWS TWEAKS (End) ######################################>



<###################################### TEST TWEAKS (Start) ######################################>
<# Tracking
Set-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowRecent" -Value "1" -Force | Out-Null
Write-Host "Explorer: Disabled 'Recent Files' in Explorer [Skipped]" -ForegroundColor Yellow

Set-ItemProperty -LiteralPath "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value "1" -Force | Out-Null
Write-Host "Explorer: Disabled Recent Files/Folders in Start Menu and Explorer [Skipped]" -ForegroundColor Yellow
#>

<# Visual Settings
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
Powercfg /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
Write-Host "Sleep Settings: Set to High Performance" -ForegroundColor Green
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

powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg -setdcvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
Write-Host "Sleep Settings: 'Closing Lid' action to turn off screen" [CHANGED] -ForegroundColor Green

Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowSleepOption' -Value 0 -Type DWord
Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings' -Name 'ShowHibernateOption' -Value 0 -Type DWord
Write-Host "Sleep Settings: Sleep/Hibernate from Start Menu [DISABLED]" -ForegroundColor Green
#endregion


<#############################################################################################################################>
#region 7.0 - Privacy
Write-Host "`n`n7.0 Privacy" -ForegroundColor Green
## Applications
Write-Host "7.1 Applications" -ForegroundColor Green
Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name 'Value' -Value 'Deny' -Type String
Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}' -Name 'SensorPermissionState' -Value 1 -Type DWord -CreatePath
Set-Registry -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration' -Name 'EnableStatus' -Value 1 -Type DWord -CreatePath
Write-Host "Applications - Location Permissions [DISABLED]" -ForegroundColor Green

Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics' -Name 'Value' -Value 'Deny' -Type String
Write-Host "Applications - Diagnostics [DISABLED]" -ForegroundColor Green

Write-Host "7.2 Keyboard" -ForegroundColor Green
Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\TextInput\AllowLinguisticDataCollection' -Name 'value' -Value 0 -Type DWord -CreatePath
Set-Registry -Path 'HKCU:\Software\Microsoft\Input\TIPC' -Name 'Enabled' -Value 0 -Type DWord -CreatePath
Write-Host "Keyboard - Improved Inking and Typing Reconition [DISABLED]" -ForegroundColor Green

Write-Host "7.3 Clipboard" -ForegroundColor Green
Set-Registry -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard' -Name 'Disabled' -Value 1 -Type DWord -CreatePath
Write-Host "Clipboard - 'Smart Clipboard' [DISABLED]" -ForegroundColor Green

Write-Host "7.4 Telemetry" -ForegroundColor Green #InTune Required
# Disable Tailored Experiences With Diagnostic Data
Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy' -Name 'TailoredExperiencesWithDiagnosticDataEnabled' -Value 0 -Type DWord
# Disable Activites
Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableActivityFeed' -Value 0 -Type DWord
Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'PublishUserActivities' -Value 0 -Type DWord
Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'UploadUserActivities' -Value 0 -Type DWord
Write-Host "Windows: Activity Feed [DISABLED]" -ForegroundColor Green
# Disable Telemetry
Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'AllowTelemetry' -Value 0 -Type DWord
Set-Registry -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -Name 'MaxTelemetryAllowed' -Value 0 -Type DWord
Set-Registry -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -Name 'AllowTelemetry' -Value 0 -Type DWord
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
#region 8.0 - Space Cleanup
Write-Host "`n`n8.0 Space Cleanup" -ForegroundColor Green
function Remove-ItemRecursively {
    param (
        [string]$Path
    )
    
    Get-ChildItem -Path $Path -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
}
## Temporary Files
# Temp - User
Remove-ItemRecursively -Path "$env:TEMP\*" -Recurse -Force
Write-Host " - Clearing C:\User\$env:username\Temp" -ForegroundColor Yellow
# Temp - Windows
Remove-ItemRecursively -Path "C:\Windows\Temp\*"
Write-Host " - Clearing C:\Windows\Temp\" -ForegroundColor Yellow
## Windows Update
Write-Host " - Clearing old Windows Updates" -ForegroundColor Yellow
Write-Host "`n*NOTE* This may take some time and is expected. Especially, if this is the first time running the script." -ForegroundColor Red
# SoftwareDistribution
## Windows Update
# SoftwareDistribution
Stop-Service -Name wuauserv
if (Test-Path "C:\Windows\SoftwareDistribution.old") {
    cmd.exe /c rd /s /q "C:\Windows\SoftwareDistribution.old"
}   # Remove any .old variations of 'SoftwareDistribution'
Rename-Item -Path "C:\Windows\SoftwareDistribution" -NewName "SoftwareDistribution.old"
cmd.exe /c rd /s /q "C:\Windows\SoftwareDistribution.old"
Start-Service -Name wuauserv
# WinSxS
# Service Pack Backups / Superseded Updates / Replaced Componets
dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
## Free Space - Retrieve Updated Free Space
$FreeSpaceAfter = (Get-PSDrive -Name C).Free / 1GB
Write-Host "`n - Disk Space Free (after): $("{0:N2} GB" -f $FreeSpaceAfter)" -ForegroundColor Yellow
Write-Host " - Actual Space Freed: $("{0:N2} GB" -f ($FreeSpaceAfter - $FreeSpaceBefore))" -ForegroundColor Green


<#############################################################################################################################>
#region 9.0 - Script Log
### Log - End
# Log
"Script Duration" | Out-File -Append -FilePath $LogFile
$Timer.Stop()
$Timer.Elapsed | Select-Object Hours, Minutes, Seconds | Format-Table | Out-File -Append -FilePath $LogFile
"Drive Space Free (before): $("{0:N2} GB" -f $FreeSpaceBefore)" | Out-File -Append -FilePath $LogFile
"Drive Space Free (after): $("{0:N2} GB" -f $FreeSpaceAfter)" | Out-File -Append -FilePath $LogFile
"Drive Space Restored: $("{0:N2} GB`n" -f ($FreeSpaceAfter - $FreeSpaceBefore))" | Out-File -Append -FilePath $LogFile
"######################################################`n" | Out-File -Append -FilePath $LogFile
# Output
Write-Host "`n`n9.0 Log: Script Duration" -ForegroundColor Green
$TimerFinal = $Timer.Elapsed | Select-Object Hours, Minutes, Seconds | Format-Table
$TimerFinal
Write-Host "Log file located at $LogFile" -ForegroundColor Yellow
#endregion


<#############################################################################################################################>
#region 9.0 - Notify User / Reboot
<#############################################################################################################################>
#region 9.0 - Notify User / Reboot
Write-Host "`n`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                                ║" -ForegroundColor Cyan
Write-Host ("║      █▓▒░  W1X Debloat Script  ░▒▓█  |  Version {0}           ║" -f $sv) -ForegroundColor Green
Write-Host "║                                                                ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════╝`n" -ForegroundColor Cyan

Write-Host "$([char]9989)  Optimization Complete`n" -ForegroundColor Cyan
Write-Host "$([char]9881)  https://github.com/AdminVin/W1X-Debloat`n" -ForegroundColor Cyan
Write-Host ">>> PLEASE REBOOT YOUR COMPUTER FOR ALL CHANGES TO TAKE EFFECT <<<`n" -ForegroundColor Red

#endregion