Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value "3"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value "393241"
New-ItemProperty -LiteralPath "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value ([byte[]](0x10,0x32,0x07,0x80,0x10,0x00,0x00,0x00)) -PropertyType Binary -Force
Write-Host "Explorer: Set Optimal Visual Settings" -ForegroundColor Green

<#
# Set the visual effects to the "Custom" option with specific settings
Import-Module SystemPropertiesClient
Set-SystemPropertiesPerformance -VisualFX "Custom" -Settings @{ "Animate controls and elements inside windows" = "Off"; "Animate windows when minimizing and maximizing" = "Off" }
#>

# Set the visual effects to the "Adjust for best performance" option
#Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name UserPreferencesMask -Value ([int]0x90)

# Set the visual effects to the "Adjust for best appearance" option
#Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name UserPreferencesMask -Value ([int]0x0)

# Set the visual effects to the "Custom" option with specific settings
$settings = @{
    "DragFullWindows" = "0"
    "FontSmoothing" = "0"
    "MenuShowDelay" = "0"
    "ListboxSmoothScrolling" = "0"
    "CursorBlinkRate" = "0"
}
$userPreferencesMask = [int]0x0
foreach ($setting in $settings.GetEnumerator()) {
    if ($setting.Value -eq "0") {
        $userPreferencesMask += [int][Math]::Pow(2, $setting.Key)
    }
}
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name UserPreferencesMask -Value $userPreferencesMask
