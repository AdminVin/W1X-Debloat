@echo OFF
echo *******************************
echo * Disabling Unneeded Services *
echo *******************************
echo *
:: Adobe
sc config AdobeARMservice start= disabled
sc config SwitchBoard start= disabled
:: Microsoft
:: .Net
sc config NetMsmqActivator start= disabled
sc config NetPipeActivator start= disabled
sc config NetTcpPortSharing start= disabled
:: ActiveX Installer (GPO Based / Domain)
sc config AxInstSV start= disabled
:: Adaptive Brightness
sc config SensrSvc start= disabled
:: Backup
sc config SDRSVC start= disabled
:: Card Space
sc config idsvc start= disabled
:: Connect Now
sc config wcncsvc start= disabled
:: Defender
sc config WinDefend start= auto
::  Distributed Link Tracking Client
sc config TrkWks start= disabled
:: Faxing
sc config Fax start= disabled
:: Internet Sharing
sc config SharedAccess start= disabled
:: IP Helper
sc config iphlpsvc start= disabled
:: Media Center Extender Service
sc config Mcx2Svc start= disabled
:: Media Player Sharing
sc config WMPNetworkSvc start= disabled
:: Offline Files
sc config CscService start= disabled
:: Portable Device Enumerator
sc config WPDBusEnum start= disabled
:: Problem Reports and Solutions
sc config wercplsupport start= disabled
:: Routing and Remote Access
sc config RemoteAccess start= disabled
:: Security Center
sc config wscsvc start= disabled
:: Sign-In Assistant
sc config wlidsvc start= disabled
:: Tablet PC Input
sc config TabletInputService start= disabled
:: Telephony 
sc config TapiSrv start= disabled
:: Windows Updates
sc config wuauserv start= auto
echo *
echo ***************************
echo * Applying Registry Fixes *
echo ***************************
echo *
:: Verbose status messages when logging in
regedit /s reg\verbose.reg
:: Num Lock Active after Reboot
regedit /s reg\numlock_active.reg
:: Foreground Application Priority
regedit /s reg\app_priority.reg
:: Take Ownership (Right-Click)
regedit /s reg\TakeOwnership.reg
:: Enhanced Shutdown
regedit /s reg\enhanced_shutdown.reg
:: Outlook Icon on Desktop (With Right Click Menu - Administration Mail Profile Adjustment)
regedit /s reg\outlook.reg
:: Aero Instant Thumbnail
regedit /s reg\aero_thumbnail.reg
:: Open With (disable internet search)
regedit /s reg\NoInternetOpenWith.reg
:: Pin Folders to Start
regedit /s reg\pinfolderstostartmenu.reg
:: OSX to PC | PC to OSX - File Sharing Made Easy
regedit /s reg\mactopcfilesharing.reg
:: Disable Last Timestamp | SSD Harddrive Optimization
regedit /s reg\disable-last-access-timestamps.reg
:: Drive Letters First in My Computer
regedit /s reg\showdrivelettersfirst.reg
:: Disable Windows Defender Reporting of Statistics
regedit /s reg\disable-reporting_windefend.reg
:: Increase Connections Allowed in Windows
regedit /s reg\maxconnectionstweak.reg
:: Disable File Warning Opening Prompt
regedit /s reg\disable-filewarning.reg
:: Disable Windows Media Player Updating Automatically
regedit /s reg\disable-windows-media-player-updates.reg
:: Hard Drive Performance Tweak
regedit /s reg\enable-ahci-windows7.reg
echo *
echo *************************
echo * HOST File Ad Blocking *
echo *************************
:: ------------EXTRA CODE TO CHANGE DIRECTORY-------------
echo %~n0%~x0 started from Directory: %~d0%~p0
%~d0
cd %~d0%~p0
:: -------------------------------------------------------

IF NOT EXIST HOSTS GOTO noHostsFile
IF "%OS%"=="Windows_NT" GOTO HostsFile
IF EXIST %winbootdir%\HOSTS*.* ATTRIB +A -H -R -S %winbootdir%\HOSTS*.*>NUL
IF EXIST %winbootdir%\HOSTS.MVP DEL %winbootdir%\HOSTS.MVP>NUL
IF EXIST %winbootdir%\HOSTS REN %winbootdir%\HOSTS HOSTS.MVP>NUL
IF EXIST %winbootdir%\NUL COPY /Y HOSTS %winbootdir%>NUL
GOTO noHostsFile
:HostsFile
IF EXIST %windir%\SYSTEM32\DRIVERS\ETC\HOSTS*.* ATTRIB +A -H -R -S %windir%\SYSTEM32\DRIVERS\ETC\HOSTS*.*>NUL
IF EXIST %windir%\SYSTEM32\DRIVERS\ETC\HOSTS.MVP DEL %windir%\SYSTEM32\DRIVERS\ETC\HOSTS.MVP>NUL
IF EXIST %windir%\SYSTEM32\DRIVERS\ETC\HOSTS REN %windir%\SYSTEM32\DRIVERS\ETC\HOSTS HOSTS.MVP>NUL
IF EXIST %windir%\SYSTEM32\DRIVERS\ETC\NUL COPY /Y HOSTS %windir%\SYSTEM32\DRIVERS\ETC>NUL
cls
echo ********************************
echo * Windows 7 Has Been Optimized *
echo ********************************
echo *
echo *
echo *
echo ***************************************************
echo * RESTART YOUR SYSTEM FOR CHANGES TO TAKE EFFECT! *
echo ***************************************************
pause
exit