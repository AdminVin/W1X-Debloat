# W1X Debloat
![Banner](https://github.com/AdminVin/W1X-Debloat/raw/main/Banner.jpg)

[![Latest Release](https://img.shields.io/github/v/release/AdminVin/W1X-Debloat?label=release)](https://github.com/AdminVin/W1X-Debloat/releases/latest)
[![Last Commit](https://img.shields.io/github/last-commit/AdminVin/W1X-Debloat)](https://github.com/AdminVin/W1X-Debloat/commits/main)
![Windows 10 | 11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?logo=windows)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)
[![License](https://img.shields.io/badge/license-Open%20Use%20%2F%20No%20Resale-lightgrey)](LICENSE.txt)

## What is W1X Debloat?
W1X (wix) Debloat is a one-click PowerShell script that optimizes your Windows 10/11 installation. Created to increase performance, remove bloatware, and more importantly stop Microsoft from spying.

- Removes preinstalled bloatware for all users
- Disables telemetry, tracking, ads, and AI data collection (Recall, Click to Do, Copilot context)
- Tunes Windows, Explorer, network, and power settings for performance and gaming
- Cleans up temp files and caches, then reports how much space was freed

<br>

## How do I run W1X Debloat?
You can either use the BAT file or the script. The bat file is recommended, as it always downloads the latest version before running. You can also download the script and run it yourself manually.

**BAT File (Recommended):** https://github.com/AdminVin/W1X-Debloat/releases/tag/Installer

**PowerShell Script:** https://github.com/AdminVin/W1X-Debloat/raw/main/W1X%20Debloat%20(W10-11).ps1

**One-Line Install:** Open PowerShell as Administrator and run:
```powershell
irm "https://raw.githubusercontent.com/AdminVin/W1X-Debloat/main/W1X%20Debloat%20(W10-11).ps1" | iex
```

<br>

### Instructions ###

____________________________________
**BAT File**
1. Download the BAT File

2. Right Click and Run As Administrator

3. Script will run and cleanup your computer.

____________________________________
**PowerShell Script**
1. Download the PowerShell Script File

2. Click Start > Search for PowerShell ISE > Right Click > Run As Administrator

3. File > Open > Browse to the file downloaded "W1X Debloat (W10-11).ps1" > Click the "Green Arrow" or press F5 to run.

4. Script will run and cleanup your computer.

<br>

## What does it change?

| Area | Highlights |
|---|---|
| **Applications** | Removes Microsoft Store bloatware (all users). Edge, OneDrive (only if unused), Teams, Cortana, and OneNote startup cleanup. Chrome, Firefox, Edge, and Office telemetry disabled. Installs Sysinternals Autoruns. |
| **Services & Tasks** | Disables telemetry, push, and unused services. Disables (not deletes) telemetry/CEIP scheduled tasks so Windows can't recreate them. |
| **AI** | Recall removed, Click to Do disabled, AI Actions menu hidden, Notepad AI disabled, Copilot page access in Edge blocked, Copilot key remapped to Context Menu. |
| **Privacy** | Telemetry, activity history, advertising ID, tailored experiences, inking/typing collection, clipboard sync, online speech, and error reporting disabled. Defender stops uploading your files. Developer tool telemetry (PowerShell 7, .NET, VS Code, Visual Studio) disabled. |
| **Explorer & Start** | Classic right-click menu, file extensions shown, Home/Gallery/Widgets removed, Start menu suggestions and web search removed, "End Task" on taskbar. |
| **Network** | Power saving, packet coalescing, and throttling disabled on adapters. Legacy TCP tweaks from older versions reverted. |
| **Performance** | High Performance power plan, Game Mode, HAGS, faster shutdown, animations and transparency off, Fast Startup and hibernate off. |
| **Cleanup** | Temp files, caches, and Windows Update leftovers for all profiles. TRIM on SSDs. |

Full details for every version: **[Change Log](changelog.md)**

<br>

## FAQ
**Is it safe to re-run?**
Yes. The script checks existing settings and can be run again after Windows updates to re-apply changes.

**Can I undo it?**
Use the restore point you created before running. Individual settings can be changed back through Settings or the registry.

**Does it work on Windows 10?**
Yes. Windows 11-specific settings are harmless on Windows 10 and simply have no effect.

**Something broke / I have a suggestion.**
Open an [issue](https://github.com/AdminVin/W1X-Debloat/issues).

<br>

## Donate
Helped your system? Great! --- Sponsor my next coffee? [PayPal](https://www.paypal.com/donate/?hosted_button_id=EZU78ZANFT24C)
