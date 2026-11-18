# W1X Debloat - Change Log

## 2026-11-18 - v1.32
- Added Privacy: Microsoft Defender automatic sample submission disabled (SubmitSamplesConsent = Never send).
  - Cloud-delivered protection remains enabled.
- Added Privacy: Click to Do disabled (DisableClickToDo policy).
- Added Privacy: Notepad AI features disabled (DisableAIFeatures policy).
- Added Explorer: 'AI Actions' right-click context menu hidden (HideAIActionsMenu policy).
- Added Explorer: Recall optional feature removed (AllowRecallEnablement = 0 + payload removal).
  - Snapshot policy (DisableAIDataAnalysis) kept so Recall stays disabled if Windows reinstalls it.
- Added Edge: Copilot page context access blocked (CopilotPageContext, EdgeEntraCopilotPageContext). Entra ID profiles only.
- Added Privacy: PowerShell 7, .NET CLI, VS Code, and Visual Studio telemetry disabled.
- Renumbered all versions.

## 2026-11-02 - v1.31
- Added Network: MIMO power saving disabled (No SMPS) on supported Wi-Fi adapters, connected or disconnected.
- Added Network: Packet Coalescing disabled on Ethernet/Wireless adapters, including disconnected adapters.
  - Batching incoming packets delays small real-time game packets, causing rubber banding in online games.

## 2026-09-16 - v1.30
- Fixed Applications: Metro apps now remove for all users ('-AllUsers' was missing, removal only applied to the account running the script).
- Fixed Applications: Package enumeration moved outside the removal loop (was re-running for every entry in the list).
- Fixed Windows 11 detection: Now uses build number instead of the OS name, which is localized and failed on non-English installs.
- Fixed Windows Update Delivery Optimization: Moved to the HKLM policy (DODownloadMode), the previous user hive path was unreliable.
- Added Windows: LSA Protection (RunAsPPL) - blocks credential dumping from LSASS.
  - Previous versions disabled this alongside VBS. It is not part of VBS and has no performance cost.
  - Set to '2' (no UEFI lock) so it remains revertible.
- Added Windows: Microsoft vulnerable driver blocklist enforced (mitigates the kernel-mode bypass for the above).
- Added Windows: Application Experience policies disabled (AITEnable/DisableInventory/DisablePCA).
  - Scheduled tasks alone were being recreated by feature updates.
- Added Windows: Telemetry ETW autologgers disabled (Diagtrack-Listener/SQMLogger).
  - These kernel trace sessions keep writing to disk even with the DiagTrack service stopped.
- Added Explorer: NTFS 8.3 short filename creation disabled.
- Added Cleanup: TRIM (Optimize-Volume -ReTrim) after the space cleanup, on SSDs only.
- Updated Services: Prefetcher/Superfetch registry values disabled on SSDs, to match the SysMain service.
- Updated Services: Telephony (TapiSrv) set to Manual instead of Disabled.
  - RasMan depends on it, disabling it can break the built-in Windows VPN client.
- Removed Explorer: 'Convert to JPG' right click menu - was non-functional, and is now cleaned up if previously added.
- Removed Network: Legacy and no-op TCP tweaks (CTCP, auto-tuning, DCA, ECN, NetDMA, IRPStackSize).
  - DCA/NetDMA target a subsystem removed in Windows 8; auto-tuning and ECN already matched the defaults.
  - CTCP is a downgrade from the modern CUBIC default.
  - CTCP and IRPStackSize are reverted on machines that ran previous versions.

## 2026-09-14 - v1.29
- Fixed Set-Registry: Now corrects existing values with the wrong registry type.
- Updated Explorer: Disabled window grouping in Taskbar and Alt+Tab (EnableTaskGroups).

## 2026-07-28 - v1.28
- Stopped Outlook (New) from being removed.
- Added Google Chrome: Disabled telemetry.
- Updated Mozilla Firefox: Disabled telemetry.
- Updated Microsoft Edge: Disabled auto start & updated disabling telemetry.
- Added Microsoft Office: Disabled telemetry.

## 2026-07-17 - v1.27
- Cleaned up output for script re-runs.

## 2026-06-30 - v1.26
- Re-enabled OneDrive removal/disable, now detected by checking if %USERPROFILE%\OneDrive has any content (empty/missing = not in use).

## 2026-06-20 - v1.25
- Disabled mandatory SMB client signing requirement (LanmanWorkstation\RequireSecuritySignature).
  - Windows 11 24H2+ made SMB signing mandatory for ALL outbound connections by default (previously only required for domain controllers).
  - Breaks anonymous/guest SMB shares (e.g. Samba "guest ok" shares) since guest sessions can't satisfy mandatory signing.

## 2026-06-08 - v1.24
- Disabled OneDrive removal &disable if not in use.
  - Current detection method is out of date, and no longer viable.

## 2026-06-01 - v1.23
- Fixed script abort risk: moved $ErrorActionPreference before counter API call.
- Fixed SSD detection null-deref when PhysicalDisk lookup returns no match on NVMe/OEM hardware.
- Added Set-CopilotToContextMenu: remaps Copilot key (F23) to Context Menu key via Scancode Map.
- Disabled NTFS Last Access Timestamp updates to reduce unnecessary disk writes.

## 2026-05-10 - v1.22
- Updated Hyper-V/Docker tweaks to re-enable if any componet is either installed.

## 2026-05-07 - v1.21
- Updated Start Menu to the modern wider design recently released by Microsoft.
  - Unable to maintain the original start menu, as the registry keys are no longer functional.
- Enabled Num Lock on startup for current user and login screen.
- Updated the cleanup of scheduled tasks to DISABLE instead of REMOVE.
  - Windows was recreating the tasks, defeating the purpose of the cleanup.

## 2026-05-05 - v1.20
- Added script counter for tracking total PC's optimized (https://counterapi.dev/).
- Updated Edge service removal.
- Updated OneDrive removal process.
- Updated Windows Suggestions/Tips/Welcome Experience removal with descriptions.
- Updated Windows 'Getting to Know You' disabling process.
- Updated Windows Cleanup to disable Windows space reservation.
- Added performance optimizations: MMCSS SystemResponsiveness, HAGS, DisablePagingExecutive, Game Mode.
- Disabled CoPilot Recall automatic screenshots.

## 2026-04-10 - v1.19
- Updated 'Cleanup' section, added additional temp/cache directories.

## 2026-03-10 - v1.18
- Updated parameters for disabling "High Precision Event Timer" and setting to "Time Stamp Counter" (CPU Clock).

## 2026-03-04 - v1.17
- Adjusted TCP Tuning for better throughput.

## 2026-02-20 - v1.16
- Removed PowerShell 7 from installing if not detected (no longer needed).

## 2026-02-11 - v1.15
- Added blocking of telementry for OneDrive and Windows Feedback.
- Disabled adding IEtoEdge Addon for Internet Explorer.

## 2026-01-25 - v1.14
- Added Windows 11 Start Menu restore (original look on release).

## 2026-01-21 - v1.13
- Added Start Menu App category removal.
- Added Taskbar right click 'End Task' option.
- OneDrive removal re-added.
  - Using key: HKEY_CURRENT_USER\Software\Microsoft\OneDrive\ClientEverSignedIn for OneDrive usage.
- Added pop up notification for script completion.

## 2025-12-09 - v1.12
- Added Bing Search and Weather for app removal.

## 2025-11-10 - v1.11
- Updated 'Cleanup'Section.
  - Added more in depth cleaning of temporary files for all user profiles and system files.

## 2025-11-04 - v1.10
- Removed "Home" shortcut in File Explorer, and disabled recommendations.
- Updated PowerShell 7 link to latest version (v7.5.4).
- Added battery percentage in system tray for mobile devices.
- Added "Startup" restore for Settings > Apps > Startup to easier manage startup items.
- Removed log and cleaned up script end output.

## 2025-10-21 - v1.9
- OneDrive removal re-added.
  - Fresh Windows installation/pre-sign in creates key: HKCU\Software\Microsoft\OneDrive\Installer\BITS\PreSignInSettingsConfigJSON
  - Signing into OneDrive removes the registry key.

## 2025-10-15 - v1.8
- Added autoruns/autoruns64 check to speed up script.

## 2025-09-19 - v1.7
- OneDrive removal commented out, until a more reliable in use/sync detection method can be identified.

## 2025-08-07 - v1.6
- Misc Code cleanup/fixes.

## 2025-08-03 - v1.5
- Updated Hyper-V tweak, skipping if Docker is installed.
- Updated OneDrive detection and cleaned up output.

## 2025-07-07 - v1.4
- Added PowerShell 7 Updater.
- Removed 'Ask Co-Pilot' from Right Click Context Menu.

## 2025-06-20 - v1.3
- Fixed progress bar bug (being stuck on screen, post operation).

## 2025-06-19 - v1.2
- Updated method to detect if OneDrive is signed in and syncing.
- Rewrote all registry modifications, to process faster with a function.
- Updated Metro apps list for removal.
- Metro apps will be removed system wide (all users).
- Updated power plan from "Balanced" to "High Performance" while retaining settings.
- Added Sysinternals "Autoruns" & "Autoruns64" to install.
  - Start > Run > autoruns to quick launch.
- Updated Scheduled Tasks & Services method.
  - Removed Windows Media Player Sharing service.
- Updated network tweaks: NetDMA; enabled RSS/DCA; set CTCP for optimized throughput and reduced latency.

## 2023-06-01 - v1.1
- PowerShell Studio compiled versions.

## 2022-07-01 - v1.0
- Initial creation of script.
