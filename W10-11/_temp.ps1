# Define the URL of the .reg file
$url = "https://github.com/AdminVin/W1X-Debloat/raw/main/W10-11/RegistryKeys/TakeOwnership_Pause.reg"

# Define the download path
$downloadPath = "C:\Temp\TakeOwnership_Pause.reg"

# Ensure the Temp directory exists
If (-not (Test-Path "C:\Temp")) {
    New-Item -ItemType Directory -Path "C:\Temp"
}

# Use WebClient to download the .reg file
$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile($url, $downloadPath)

# Execute the downloaded .reg file
$command = "regedit /s `"$downloadPath`""
Invoke-Expression $command


# Clean up: Remove the .reg file after execution
Remove-Item -Path $downloadPath -Force
