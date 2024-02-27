# Define the URL of the .reg file
$url = "https://github.com/AdminVin/W1X-Debloat/raw/main/W10-11/RegistryKeys/TakeOwnership_Pause.reg"

# Define the download path
$downloadPath = "C:\ProgramData\AV\Temp\TakeOwnership_Pause.reg"

# Ensure the Temp directory exists
If (-not (Test-Path "C:\ProgramData\AV\Temp\")) {
    New-Item -ItemType Directory -Path "C:\ProgramData\AV\Temp\"
}

# Use WebClient to download the .reg file
$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile($url, $downloadPath)

# Execute the downloaded .reg file
Start-Process "regedit.exe" -ArgumentList "/s", $downloadPath -Wait -NoNewWindow


# Clean up: Remove the .reg file after execution
Remove-Item -Path "C:\ProgramData\AV\Temp" -Recurse -Force
