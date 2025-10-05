$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$log = "$env:USERPROFILE\hSpecs_$ts.txt"

function EchoHeader($t) { "=== $t ===" | Tee-Object -FilePath $log -Append }
function EchoData($d) {
  $d | Format-Table -AutoSize -Wrap | Tee-Object -FilePath $log -Append
  "" | Tee-Object -FilePath $log -Append
}

EchoHeader "System Identity"
EchoData (Get-CimInstance Win32_ComputerSystem | Select Name, Manufacturer, Model)

EchoHeader "Operating System"
EchoData (Get-CimInstance Win32_OperatingSystem | Select Caption, Version, BuildNumber, OSArchitecture, @{N="InstallDate";E={($_.InstallDate).ToLocalTime()}})

EchoHeader "Install History (Registry)"
try {
  $installs = Get-ChildItem -Path HKLM:\System\Setup\Source* |
    ForEach-Object { Get-ItemProperty -Path Registry::$_ } |
    Select-Object ProductName, ReleaseID, CurrentBuild,
      @{Name='InstallDate'; Expression={ [timezone]::CurrentTimeZone.ToLocalTime(( [datetime]'1/1/1970').AddSeconds($_.InstallDate)) }} |
    Sort-Object InstallDate
  EchoData $installs
} catch {
  "Install history not available." | Tee-Object -FilePath $log -Append
  "" | Tee-Object -FilePath $log -Append
}

EchoHeader "Activation (Windows)"
$licenses = Get-CimInstance SoftwareLicensingProduct | Where-Object { $_.PartialProductKey }
$decoded = $licenses | Select-Object Description, LicenseStatus, @{Name="StatusText";Expression={
  switch ($_.LicenseStatus) {
    0 { "Unlicensed" }
    1 { "Licensed" }
    2 { "Out-of-Box Grace" }
    3 { "Out-of-Tolerance Grace" }
    4 { "Non-Genuine Grace" }
    5 { "Notification Mode" }
    6 { "Extended Grace" }
    default { "Unknown" }
  }
}}
EchoData $decoded

EchoHeader "CPU"
EchoData (Get-CimInstance Win32_Processor | Select Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed)

EchoHeader "RAM Modules"
$ram = Get-CimInstance Win32_PhysicalMemory
EchoData ($ram | Select Manufacturer, SerialNumber, PartNumber, BankLabel, @{N="GB";E={"{0:N0}" -f ($_.Capacity / 1GB)}}, Speed, ConfiguredClockSpeed)

$mismatched = $ram | Where-Object { $_.Speed -ne $_.ConfiguredClockSpeed }
if ($mismatched) {
  'RAM speed mismatch detected - BIOS may be underclocking modules.' | Tee-Object -FilePath $log -Append
  "" | Tee-Object -FilePath $log -Append
}

EchoHeader "Total RAM"
"{0:N0} GB" -f (($ram | Measure-Object Capacity -Sum).Sum / 1GB) | Tee-Object -FilePath $log -Append
"" | Tee-Object -FilePath $log -Append
"Checkpoint: Total RAM block completed" | Tee-Object -FilePath $log -Append
"" | Tee-Object -FilePath $log -Append

EchoHeader "Motherboard"
EchoData (Get-CimInstance Win32_BaseBoard | Select Manufacturer, Product, SerialNumber)

EchoHeader "GPU"
EchoData (Get-CimInstance Win32_VideoController | Where Name -notlike "*Idd*" | Select Name, @{N="RAM(GB)";E={"{0:N1}" -f ($_.AdapterRAM / 1GB)}}, DriverVersion)

EchoHeader "Display Devices (Active + Registry)"
$active = Get-CimInstance Win32_DesktopMonitor | Select Name, ScreenHeight, ScreenWidth, DeviceID
EchoData $active

$regDisplays = Get-ChildItem -Path Registry::HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY -ErrorAction SilentlyContinue |
  ForEach-Object {
    try {
      $id = $_.PSChildName
      Get-ChildItem -Path $_.PSPath -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch "Device Parameters" } |
        ForEach-Object {
          $subid = $_.PSChildName
          $edid = (Get-ItemProperty -Path "$($_.PSPath)\Device Parameters" -ErrorAction Stop).EDID
          $serial = if ($edid) { [System.Text.Encoding]::ASCII.GetString($edid[12..27]) -replace '\W','' } else { "" }
          $vendor = switch -regex ($id) {
            '^DEL' { 'Dell' }
            '^SAM' { 'Samsung' }
            '^LGD' { 'LG Display' }
            '^ACR' { 'Acer' }
            '^PHL' { 'Philips' }
            '^BNQ' { 'BenQ' }
            '^HWP' { 'HP' }
            '^LEN' { 'Lenovo' }
            '^ASU' { 'ASUS' }
            '^APP' { 'Apple' }
            default { 'Unknown' }
          }
          [PSCustomObject]@{
            DisplayID    = $id
            Manufacturer = $vendor
            SubID        = $subid
            Serial       = $serial
          }
        }
    } catch {}
  }

if ($regDisplays) {
  "Detected display registry entries:" | Tee-Object -FilePath $log -Append
  $regDisplays | Format-Table -AutoSize | Tee-Object -FilePath $log -Append
  "" | Tee-Object -FilePath $log -Append
} else {
  "No inactive display registry entries found." | Tee-Object -FilePath $log -Append
  "" | Tee-Object -FilePath $log -Append
}

EchoHeader "Disk Drives"
EchoData (Get-CimInstance Win32_DiskDrive | Select Model, InterfaceType, MediaType, @{N="Size(GB)";E={"{0:N0}" -f ($_.Size / 1GB)}})

EchoHeader "BIOS"
EchoData (Get-CimInstance Win32_BIOS | Select Manufacturer, SMBIOSBIOSVersion, @{N="ReleaseDate";E={($_.ReleaseDate).ToLocalTime()}})

EchoHeader "TPM"
try {
  $tpm = Get-Tpm | Select TpmPresent, ManufacturerID, ManufacturerVersion, SpecVersion, IsActivated
  EchoData $tpm
} catch {
  "TPM info not available." | Tee-Object -FilePath $log -Append
  "" | Tee-Object -FilePath $log -Append
  $tpm = [PSCustomObject]@{ TpmPresent = "Unavailable"; ManufacturerID = ""; ManufacturerVersion = ""; SpecVersion = ""; IsActivated = "" }
}

EchoHeader "Secure Boot"
try {
  $secureBoot = [PSCustomObject]@{ Status = if (Confirm-SecureBootUEFI) { "Enabled" } else { "Disabled" } }
  EchoData $secureBoot
} catch {
  "Secure Boot info not available." | Tee-Object -FilePath $log -Append
  "" | Tee-Object -FilePath $log -Append
  $secureBoot = [PSCustomObject]@{ Status = "Unavailable" }
}

EchoHeader "Office Activation (OSPP.VBS)"
$osppPaths = @(
  "C:\Program Files\Microsoft Office\root\Office16\OSPP.VBS",
  "C:\Program Files (x86)\Microsoft Office\root\Office16\OSPP.VBS"
)

$officeStatus = @()
foreach ($path in $osppPaths) {
  if (Test-Path $path) {
    $output = cscript.exe //nologo $path /dstatus
    $lines = $output -split "`n" | Where-Object { $_ -match "LICENSE STATUS|ERROR CODE|LICENSE DESCRIPTION" }
    $status = ($lines | Where-Object { $_ -match "LICENSE STATUS" }) -replace ".*LICENSE STATUS:\s*", ""
    $error = ($lines | Where-Object { $_ -match "ERROR CODE" }) -replace ".*ERROR CODE:\s*", ""
    $desc  = ($lines | Where-Object { $_ -match "LICENSE DESCRIPTION" }) -replace ".*LICENSE DESCRIPTION:\s*", ""

    $officeStatus += [PSCustomObject]@{
      Status      = $status
      ErrorCode   = $error
      Description = $desc
    }

    "Status: $status" | Tee-Object -FilePath $log -Append
    "Error Code: $error" | Tee-Object -FilePath $log -Append
    "Description: $desc" | Tee-Object -FilePath $log -Append

    if ($status -match "NOTIFICATIONS" -or $desc -match "Grace") {
      'Ghost license detected - Office may be running on an expired retail stub.' | Tee-Object -FilePath $log -Append
    }

    "" | Tee-Object -FilePath $log -Append
  }
}

if (-not $officeStatus) {
  'OSPP.VBS not found - Office activation status unavailable.' | Tee-Object -FilePath $log -Append
  "" | Tee-Object -FilePath $log -Append
  $officeStatus = [PSCustomObject]@{ Status = "Unavailable"; ErrorCode = ""; Description = "" }
}

EchoHeader "Exporting Report"

$report = [ordered]@{
  SystemIdentity     = Get-CimInstance Win32_ComputerSystem | Select Name, Manufacturer, Model
  OperatingSystem    = Get-CimInstance Win32_OperatingSystem | Select Caption, Version, BuildNumber, OSArchitecture, @{N="InstallDate";E={($_.InstallDate).ToLocalTime()}}
  InstallHistory     = $installs
  ActivationWindows  = $decoded
  CPU                = Get-CimInstance Win32_Processor | Select Name, NumberOfCores, NumberOfLogicalProcessors, MaxClockSpeed
  RAMModules         = $ram | Select Manufacturer, SerialNumber, PartNumber, BankLabel, @{N="GB";E={"{0:N0}" -f ($_.Capacity / 1GB)}}, Speed, ConfiguredClockSpeed
  Motherboard        = Get-CimInstance Win32_BaseBoard | Select Manufacturer, Product, SerialNumber
  GPU                = Get-CimInstance Win32_VideoController | Where Name -notlike "*Idd*" | Select Name, @{N="RAM(GB)";E={"{0:N1}" -f ($_.AdapterRAM / 1GB)}}, DriverVersion
  Displays           = $active
  DisplayRegistry    = $regDisplays
  DiskDrives         = Get-CimInstance Win32_DiskDrive | Select Model, InterfaceType, MediaType, @{N="Size(GB)";E={"{0:N0}" -f ($_.Size / 1GB)}}
  BIOS               = Get-CimInstance Win32_BIOS | Select Manufacturer, SMBIOSBIOSVersion, @{N="ReleaseDate";E={($_.ReleaseDate).ToLocalTime()}}
  TPM                = $tpm
  SecureBoot         = $secureBoot
  OfficeActivation   = $officeStatus
}

# Sort InstallHistory for HTML consistency
if ($report.Contains("InstallHistory")) {
  $report["InstallHistory"] = $report["InstallHistory"] | Sort-Object "InstallDate"
}

# Export to JSON
$report | ConvertTo-Json -Depth 4 | Out-File "$env:USERPROFILE\hSpecs_$ts.json"

# Flatten for CSV
$flat = foreach ($key in $report.Keys) {
  foreach ($item in $report[$key]) {
    $item | Add-Member -NotePropertyName Section -NotePropertyValue $key -Force
    $item
  }
}
$flat | Export-Csv "$env:USERPROFILE\hSpecs_$ts.csv" -NoTypeInformation

# Export to HTML (excluding Section column)
$htmlPath = "$env:USERPROFILE\hSpecs_$ts.html"
$html = @"
<!DOCTYPE html>
<html>
<head>
  <meta charset='UTF-8'>
  <title>hSpecs Report</title>
  <style>
    body { font-family: Consolas, monospace; background: #f9f9f9; color: #222; padding: 20px; }
    h2 { border-bottom: 1px solid #ccc; margin-top: 30px; }
    table { border-collapse: collapse; width: 100%; margin-top: 10px; }
    th, td { border: 1px solid #ccc; padding: 6px; text-align: left; }
    th { background: #eee; }
  </style>
</head>
<body>
  <h1>hSpecs Report</h1>
"@

foreach ($section in $report.Keys) {
  $html += "<h2>$section</h2>`n"
  $clean = $report[$section] | ForEach-Object {
    $_ | Select-Object -Property * -ExcludeProperty Section
  }
  $html += ($clean | ConvertTo-Html -Fragment | Out-String)
}

$html += "</body></html>"
$html | Out-File $htmlPath -Encoding UTF8

# Launch HTML in default browser
Start-Process $htmlPath

"Export complete. JSON, CSV, and HTML saved to: $env:USERPROFILE" | Tee-Object -FilePath $log -Append
"" | Tee-Object -FilePath $log -Append
"Spec ritual complete. Logged to: $log" | Tee-Object -FilePath $log -Append
