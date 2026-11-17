<#
.SYNOPSIS
    Bhima Tech Windows Endpoint Audit Script

.DESCRIPTION
    Collects Windows OS information, hardware inventory, installed applications,
    installed patches, missing/available Windows updates, pending reboot status,
    Windows Update health, basic security status, and support-related services.

    It generates:
    - A professional HTML report opened on screen
    - CSV exports for Excel / documentation

.NOTES
    Author: Gangadhar | Bhima Tech IT Support
    Recommended: Run from Windows PowerShell 5.1 as Administrator
    The script is read-only. Missing update scan may contact Microsoft/WSUS.
#>

[CmdletBinding()]
param(
    [switch]$SkipWindowsUpdate,
    [switch]$NoPause,
    [string]$OutputParentPath = ""
)

$ErrorActionPreference = "SilentlyContinue"

$ComputerName = $env:COMPUTERNAME
$GeneratedOn = Get-Date
$Timestamp = $GeneratedOn.ToString("yyyyMMdd_HHmmss")

# =========================
# Helper Functions
# =========================

function Write-Step {
    param([string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-ErrMsg {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Clean-Text {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    return ([string]$Value).Trim()
}

function Join-Value {
    param([object]$Value)
    if ($null -eq $Value) { return "" }

    if ($Value -is [array]) {
        return (@($Value | Where-Object { $null -ne $_ -and $_ -ne "" } | ForEach-Object { $_.ToString() }) -join "; ")
    }

    return [string]$Value
}

function Convert-SizeGB {
    param([double]$Bytes)
    if ($Bytes -le 0) { return 0 }
    return [math]::Round($Bytes / 1GB, 2)
}

function Convert-SizeMB {
    param([double]$Bytes)
    if ($Bytes -le 0) { return 0 }
    return [math]::Round($Bytes / 1MB, 2)
}

function Convert-RegistryDate {
    param([object]$Value)

    if ([string]::IsNullOrWhiteSpace([string]$Value)) { return "" }

    $text = [string]$Value

    if ($text -match '^\d{8}$') {
        try {
            return ([datetime]::ParseExact($text, "yyyyMMdd", $null)).ToString("yyyy-MM-dd")
        } catch {
            return $text
        }
    }

    return $text
}

function New-HtmlTableSection {
    param(
        [string]$Title,
        [object]$Data,
        [string]$EmptyMessage = "No records found."
    )

    $html = "<section class='card'><h2>$Title</h2>"

    if ($null -eq $Data) {
        $html += "<p class='empty'>$EmptyMessage</p></section>"
        return $html
    }

    $dataArray = @($Data)

    if ($dataArray.Count -eq 0 -or ($dataArray.Count -eq 1 -and $null -eq $dataArray[0])) {
        $html += "<p class='empty'>$EmptyMessage</p></section>"
        return $html
    }

    $table = ($dataArray | ConvertTo-Html -Fragment -As Table | Out-String)
    $html += "<div class='table-wrap'>$table</div></section>"

    return $html
}

# =========================
# Collection Functions
# =========================

function Get-InstalledApplications {
    $regPaths = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; Source = "HKLM 64-bit / Native" },
        @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; Source = "HKLM 32-bit / WOW6432" },
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; Source = "HKCU 64-bit / Native" },
        @{ Path = "HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; Source = "HKCU 32-bit / WOW6432" }
    )

    $results = foreach ($reg in $regPaths) {
        if (Test-Path $reg.Path) {
            Get-ItemProperty -Path $reg.Path -ErrorAction SilentlyContinue |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_.DisplayName) } |
                ForEach-Object {
                    $sizeMB = if ($_.EstimatedSize) {
                        [math]::Round((([double]$_.EstimatedSize * 1KB) / 1MB), 2)
                    } else {
                        ""
                    }

                    [pscustomobject]@{
                        ApplicationName  = Clean-Text $_.DisplayName
                        Version          = Clean-Text $_.DisplayVersion
                        Publisher        = Clean-Text $_.Publisher
                        InstalledOn      = Convert-RegistryDate -Value $_.InstallDate
                        Size_MB          = $sizeMB
                        InstallLocation  = Clean-Text $_.InstallLocation
                        UninstallString  = Clean-Text $_.UninstallString
                        RegistrySource   = $reg.Source
                        RegistryKey      = Clean-Text $_.PSChildName
                        SystemComponent  = if ($_.SystemComponent -eq 1) { "Yes" } else { "No" }
                    }
                }
        }
    }

    if ($null -eq $results) { return @() }
    return @($results | Sort-Object ApplicationName, Version, Publisher)
}

function Get-OsInfo {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object -First 1
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -First 1
    $cv = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue

    $bootTime = $os.LastBootUpTime
    $uptime = if ($bootTime) { (Get-Date) - $bootTime } else { $null }

    $uptimeText = if ($uptime) {
        "$([math]::Floor($uptime.TotalDays)) days $($uptime.Hours) hrs $($uptime.Minutes) mins"
    } else {
        ""
    }

    [pscustomobject]@{
        ComputerName        = $ComputerName
        WindowsProductName  = if ($cv.ProductName) { $cv.ProductName } else { $os.Caption }
        WindowsVersion      = $os.Version
        DisplayVersion      = $cv.DisplayVersion
        ReleaseId           = $cv.ReleaseId
        CurrentBuild        = $cv.CurrentBuild
        UBR                 = $cv.UBR
        FullBuild           = if ($cv.CurrentBuild -and $cv.UBR) { "$($cv.CurrentBuild).$($cv.UBR)" } else { $os.BuildNumber }
        EditionID           = $cv.EditionID
        InstallationType    = $cv.InstallationType
        OSArchitecture      = $os.OSArchitecture
        SystemType          = $cs.SystemType
        DomainOrWorkgroup   = $cs.Domain
        PartOfDomain        = $cs.PartOfDomain
        CurrentUser         = $cs.UserName
        OSInstalledOn       = $os.InstallDate
        LastBootTime        = $bootTime
        Uptime              = $uptimeText
        WindowsDirectory    = $os.WindowsDirectory
        SystemDirectory     = $os.SystemDirectory
        TimeZone            = [System.TimeZoneInfo]::Local.Id
        PowerShellVersion   = $PSVersionTable.PSVersion.ToString()
    }
}

function Get-HardwareSummary {
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select-Object -First 1
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue | Select-Object -First 1
    $enclosure = Get-CimInstance Win32_SystemEnclosure -ErrorAction SilentlyContinue | Select-Object -First 1
    $cpu = @(Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue)

    $cpuNames = Join-Value ($cpu | ForEach-Object { $_.Name })
    $cpuCores = ($cpu | Measure-Object -Property NumberOfCores -Sum).Sum
    $logicalProcessors = ($cpu | Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum

    [pscustomobject]@{
        Manufacturer        = Clean-Text $cs.Manufacturer
        Model               = Clean-Text $cs.Model
        SystemType          = Clean-Text $cs.SystemType
        SerialNumber        = Clean-Text $bios.SerialNumber
        AssetTag            = Clean-Text $enclosure.SMBIOSAssetTag
        ChassisTypes        = Join-Value $enclosure.ChassisTypes
        BIOSManufacturer    = Clean-Text $bios.Manufacturer
        BIOSVersion         = Clean-Text $bios.SMBIOSBIOSVersion
        BIOSReleaseDate     = $bios.ReleaseDate
        CPU                 = $cpuNames
        CPUCores            = $cpuCores
        LogicalProcessors   = $logicalProcessors
        TotalRAM_GB         = if ($cs.TotalPhysicalMemory) { Convert-SizeGB $cs.TotalPhysicalMemory } else { "" }
        DomainOrWorkgroup   = Clean-Text $cs.Domain
        CurrentUser         = Clean-Text $cs.UserName
    }
}

function Get-MemoryModules {
    $items = @(Get-CimInstance Win32_PhysicalMemory -ErrorAction SilentlyContinue)
    $out = @()

    foreach ($m in $items) {
        $out += [pscustomobject]@{
            BankLabel              = Clean-Text $m.BankLabel
            DeviceLocator          = Clean-Text $m.DeviceLocator
            Capacity_GB            = Convert-SizeGB $m.Capacity
            Speed_MHz              = $m.Speed
            ConfiguredSpeed_MHz    = $m.ConfiguredClockSpeed
            Manufacturer           = Clean-Text $m.Manufacturer
            PartNumber             = Clean-Text $m.PartNumber
            SerialNumber           = Clean-Text $m.SerialNumber
        }
    }

    return @($out | Sort-Object BankLabel, DeviceLocator)
}

function Get-DiskDrives {
    $items = @(Get-CimInstance Win32_DiskDrive -ErrorAction SilentlyContinue)
    $out = @()

    foreach ($d in $items) {
        $out += [pscustomobject]@{
            DeviceID        = Clean-Text $d.DeviceID
            Model           = Clean-Text $d.Model
            InterfaceType   = Clean-Text $d.InterfaceType
            MediaType       = Clean-Text $d.MediaType
            Size_GB         = Convert-SizeGB $d.Size
            Partitions      = $d.Partitions
            Status          = Clean-Text $d.Status
            SerialNumber    = Clean-Text $d.SerialNumber
            FirmwareRevision= Clean-Text $d.FirmwareRevision
        }
    }

    return @($out | Sort-Object DeviceID)
}

function Get-LogicalDisks {
    $items = @(Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue)
    $out = @()

    foreach ($d in $items) {
        $freePercent = if ($d.Size) { [math]::Round((($d.FreeSpace / $d.Size) * 100), 2) } else { "" }

        $out += [pscustomobject]@{
            Drive           = Clean-Text $d.DeviceID
            VolumeName      = Clean-Text $d.VolumeName
            FileSystem      = Clean-Text $d.FileSystem
            Size_GB         = Convert-SizeGB $d.Size
            Free_GB         = Convert-SizeGB $d.FreeSpace
            Used_GB         = if ($d.Size -and $d.FreeSpace) { Convert-SizeGB ($d.Size - $d.FreeSpace) } else { "" }
            FreePercent     = $freePercent
            VolumeSerial    = Clean-Text $d.VolumeSerialNumber
        }
    }

    return @($out | Sort-Object Drive)
}

function Get-NetworkAdapters {
    $items = @(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPEnabled })
    $out = @()

    foreach ($n in $items) {
        $out += [pscustomobject]@{
            AdapterName        = Clean-Text $n.Description
            MACAddress         = Clean-Text $n.MACAddress
            IPAddress          = Join-Value $n.IPAddress
            IPSubnet           = Join-Value $n.IPSubnet
            DefaultGateway     = Join-Value $n.DefaultIPGateway
            DNSServers         = Join-Value $n.DNSServerSearchOrder
            DHCPEnabled        = $n.DHCPEnabled
            DHCPServer         = Clean-Text $n.DHCPServer
            DNSHostName        = Clean-Text $n.DNSHostName
            DNSDomain          = Clean-Text $n.DNSDomain
        }
    }

    return @($out | Sort-Object AdapterName)
}

function Get-VideoControllers {
    $items = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue)
    $out = @()

    foreach ($v in $items) {
        $out += [pscustomobject]@{
            Name                = Clean-Text $v.Name
            AdapterRAM_GB       = Convert-SizeGB $v.AdapterRAM
            DriverVersion       = Clean-Text $v.DriverVersion
            DriverDate          = $v.DriverDate
            VideoProcessor      = Clean-Text $v.VideoProcessor
            CurrentResolution   = "$($v.CurrentHorizontalResolution) x $($v.CurrentVerticalResolution)"
            Status              = Clean-Text $v.Status
        }
    }

    return @($out | Sort-Object Name)
}

function Get-PrinterInfo {
    $items = @(Get-CimInstance Win32_Printer -ErrorAction SilentlyContinue)
    $out = @()

    foreach ($p in $items) {
        $out += [pscustomobject]@{
            PrinterName     = Clean-Text $p.Name
            Default         = if ($p.Default) { "Yes" } else { "No" }
            Shared          = if ($p.Shared) { "Yes" } else { "No" }
            Network         = if ($p.Network) { "Yes" } else { "No" }
            WorkOffline     = if ($p.WorkOffline) { "Yes" } else { "No" }
            DriverName      = Clean-Text $p.DriverName
            PortName        = Clean-Text $p.PortName
            Status          = Clean-Text $p.Status
        }
    }

    return @($out | Sort-Object PrinterName)
}

function Get-InstalledPatches {
    $items = @(Get-HotFix -ErrorAction SilentlyContinue | Sort-Object InstalledOn -Descending)
    $out = @()

    foreach ($h in $items) {
        $out += [pscustomobject]@{
            HotFixID            = Clean-Text $h.HotFixID
            InstalledOn         = $h.InstalledOn
            Description         = Clean-Text $h.Description
            InstalledBy         = Clean-Text $h.InstalledBy
            FixComments         = Clean-Text $h.FixComments
            ServicePackInEffect = Clean-Text $h.ServicePackInEffect
        }
    }

    return @($out)
}

function New-MissingPatchRow {
    param(
        [string]$Status = "",
        [string]$Title = "",
        [string]$KB = "",
        [string]$Severity = "",
        [string]$Category = "",
        [string]$Size_MB = "",
        [string]$IsDownloaded = "",
        [string]$IsMandatory = "",
        [string]$RebootBehavior = "",
        [string]$SecurityBulletins = "",
        [string]$SupportUrl = "",
        [string]$UpdateType = "",
        [string]$Description = ""
    )

    [pscustomobject]@{
        Status              = $Status
        Title               = $Title
        KB                  = $KB
        Severity            = $Severity
        Category            = $Category
        Size_MB             = $Size_MB
        IsDownloaded        = $IsDownloaded
        IsMandatory         = $IsMandatory
        RebootBehavior      = $RebootBehavior
        SecurityBulletins   = $SecurityBulletins
        SupportUrl          = $SupportUrl
        UpdateType          = $UpdateType
        Description         = $Description
    }
}

function Get-MissingPatches {
    if ($SkipWindowsUpdate) {
        return @(New-MissingPatchRow -Status "Skipped" -Title "Windows Update scan skipped by -SkipWindowsUpdate parameter." -UpdateType "Scan")
    }

    try {
        Write-Step "Checking missing / available Windows updates"
        Write-WarnMsg "This may take 1-5 minutes depending on Windows Update, WSUS, or internet connectivity."

        $Session = New-Object -ComObject Microsoft.Update.Session
        try { $Session.ClientApplicationID = "Bhima Tech IT Audit Script" } catch {}

        $Searcher = $Session.CreateUpdateSearcher()
        try { $Searcher.Online = $true } catch {}

        $SearchResult = $Searcher.Search("IsInstalled=0 and Type='Software' and IsHidden=0")

        $updates = @()
        foreach ($u in $SearchResult.Updates) {
            $updates += $u
        }

        if ($updates.Count -eq 0) {
            return @(New-MissingPatchRow -Status "Compliant" -Title "No missing software updates detected by Windows Update / WSUS." -UpdateType "Scan")
        }

        $out = @()

        foreach ($u in $updates) {
            $kbList = @()
            try {
                foreach ($kb in $u.KBArticleIDs) {
                    $kbList += "KB$kb"
                }
            } catch {}

            $categories = @()
            try {
                foreach ($cat in $u.Categories) {
                    $categories += $cat.Name
                }
            } catch {}

            $bulletins = @()
            try {
                foreach ($b in $u.SecurityBulletinIDs) {
                    $bulletins += $b
                }
            } catch {}

            $reboot = "Unknown"
            try {
                $rb = [int]$u.InstallationBehavior.RebootBehavior
                if ($rb -eq 0) { $reboot = "Never" }
                elseif ($rb -eq 1) { $reboot = "Always" }
                elseif ($rb -eq 2) { $reboot = "Can request" }
            } catch {}

            $description = ((Clean-Text $u.Description) -replace '<[^>]+>', ' ')
            if ($description.Length -gt 500) {
                $description = $description.Substring(0, 500) + "..."
            }

            $out += New-MissingPatchRow `
                -Status "Missing" `
                -Title (Clean-Text $u.Title) `
                -KB ($kbList -join ", ") `
                -Severity (Clean-Text $u.MsrcSeverity) `
                -Category ($categories -join "; ") `
                -Size_MB (Convert-SizeMB $u.MaxDownloadSize) `
                -IsDownloaded ([string]$u.IsDownloaded) `
                -IsMandatory ([string]$u.IsMandatory) `
                -RebootBehavior $reboot `
                -SecurityBulletins ($bulletins -join ", ") `
                -SupportUrl (Clean-Text $u.SupportUrl) `
                -UpdateType (Clean-Text $u.Type) `
                -Description $description
        }

        return @($out | Sort-Object Severity, Title)
    }
    catch {
        return @(New-MissingPatchRow -Status "Unavailable" -Title "Unable to query missing updates: $($_.Exception.Message)" -UpdateType "Scan")
    }
}

function Get-WindowsUpdateHealth {
    $detect = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect" -ErrorAction SilentlyContinue
    $download = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Download" -ErrorAction SilentlyContinue
    $install = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install" -ErrorAction SilentlyContinue
    $wuPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -ErrorAction SilentlyContinue
    $auPolicy = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ErrorAction SilentlyContinue
    $wuSvc = Get-CimInstance Win32_Service -Filter "Name='wuauserv'" -ErrorAction SilentlyContinue | Select-Object -First 1
    $bitsSvc = Get-CimInstance Win32_Service -Filter "Name='BITS'" -ErrorAction SilentlyContinue | Select-Object -First 1

    [pscustomobject]@{
        LastDetectSuccessTime   = $detect.LastSuccessTime
        LastDownloadSuccessTime = $download.LastSuccessTime
        LastInstallSuccessTime  = $install.LastSuccessTime
        WindowsUpdateService    = $wuSvc.State
        WindowsUpdateStartMode  = $wuSvc.StartMode
        BITSService             = $bitsSvc.State
        BITSStartMode           = $bitsSvc.StartMode
        WSUS_WUServer           = $wuPolicy.WUServer
        WSUS_WUStatusServer     = $wuPolicy.WUStatusServer
        AUOptions               = $auPolicy.AUOptions
        UseWUServer             = $auPolicy.UseWUServer
    }
}

function Get-PendingReboot {
    $reasons = @()

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        $reasons += "Component Based Servicing RebootPending"
    }

    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
        $reasons += "Windows Update RebootRequired"
    }

    $sessionManager = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
    if ($sessionManager -and $sessionManager.PendingFileRenameOperations) {
        $reasons += "PendingFileRenameOperations"
    }

    [pscustomobject]@{
        PendingReboot = if ($reasons.Count -gt 0) { "Yes" } else { "No" }
        Reasons       = if ($reasons.Count -gt 0) { $reasons -join "; " } else { "None detected" }
    }
}

function Get-AntivirusProducts {
    try {
        $rows = @(Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object {
            $stateHex = ""
            try { $stateHex = "0x{0:X6}" -f [int]$_.ProductState } catch {}

            [pscustomobject]@{
                DisplayName             = Clean-Text $_.DisplayName
                ProductStateHex         = $stateHex
                Timestamp               = Clean-Text $_.Timestamp
                PathToSignedProductExe  = Clean-Text $_.pathToSignedProductExe
                PathToSignedReportingExe= Clean-Text $_.pathToSignedReportingExe
            }
        })
        return $rows
    } catch {
        return @()
    }
}

function Get-FirewallProfiles {
    try {
        return @(Get-NetFirewallProfile -ErrorAction Stop | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction, LogAllowed, LogBlocked)
    } catch {
        return @()
    }
}

function Get-BitLockerVolumes {
    try {
        $rows = @(Get-BitLockerVolume -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                MountPoint              = Clean-Text $_.MountPoint
                VolumeStatus            = Clean-Text $_.VolumeStatus
                ProtectionStatus        = Clean-Text $_.ProtectionStatus
                EncryptionPercentage    = $_.EncryptionPercentage
                KeyProtectors           = Join-Value ($_.KeyProtector.KeyProtectorType)
            }
        })
        return $rows
    } catch {
        return @()
    }
}

function Get-ServiceAudit {
    $serviceNames = @(
        "wuauserv",
        "BITS",
        "CryptSvc",
        "msiserver",
        "EventLog",
        "Winmgmt",
        "LanmanWorkstation",
        "Dnscache"
    )

    $filter = ($serviceNames | ForEach-Object { "Name='$_'" }) -join " OR "

    $rows = @(Get-CimInstance Win32_Service -Filter $filter -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, State, StartMode, StartName, PathName)
    return $rows
}

# =========================
# Main Execution
# =========================

Write-Step "BHIMA TECH WINDOWS ENDPOINT AUDIT"

$isAdmin = Test-IsAdmin

if ($isAdmin) {
    Write-Ok "Administrator privileges detected."
} else {
    Write-WarnMsg "Not running as Administrator. Some hardware, BitLocker, firewall, or service details may be incomplete."
}

if ([string]::IsNullOrWhiteSpace($OutputParentPath)) {
    $OutputParentPath = [Environment]::GetFolderPath("Desktop")
}

if ([string]::IsNullOrWhiteSpace($OutputParentPath) -or -not (Test-Path $OutputParentPath)) {
    $OutputParentPath = $env:TEMP
}

$ReportFolder = Join-Path $OutputParentPath ("BhimaTech_IT_Audit_{0}_{1}" -f $ComputerName, $Timestamp)
New-Item -ItemType Directory -Path $ReportFolder -Force | Out-Null

$HtmlReport = Join-Path $ReportFolder "BhimaTech_IT_Audit_Report.html"

Write-Step "Collecting Windows, hardware, application, patch, and security information"

$OsInfo             = Get-OsInfo
$HardwareSummary    = Get-HardwareSummary
$MemoryModules      = @(Get-MemoryModules)
$DiskDrives         = @(Get-DiskDrives)
$LogicalDisks       = @(Get-LogicalDisks)
$NetworkAdapters    = @(Get-NetworkAdapters)
$VideoControllers   = @(Get-VideoControllers)
$Printers           = @(Get-PrinterInfo)
$Apps               = @(Get-InstalledApplications)
$InstalledPatches   = @(Get-InstalledPatches)
$MissingPatches     = @(Get-MissingPatches)
$WindowsUpdateHealth= Get-WindowsUpdateHealth
$PendingReboot      = Get-PendingReboot
$AntivirusProducts  = @(Get-AntivirusProducts)
$FirewallProfiles   = @(Get-FirewallProfiles)
$BitLockerVolumes   = @(Get-BitLockerVolumes)
$ServiceAudit       = @(Get-ServiceAudit)

$appCount = @($Apps).Count
$installedPatchCount = @($InstalledPatches).Count
$missingActualCount = @($MissingPatches | Where-Object { $_.Status -eq "Missing" }).Count

$wuScanStatus = "Unknown"
if (@($MissingPatches).Count -gt 0) {
    $wuScanStatus = @($MissingPatches)[0].Status
}

switch ($wuScanStatus) {
    "Missing"    { $missingDisplay = [string]$missingActualCount }
    "Compliant"  { $missingDisplay = "0" }
    default      { $missingDisplay = $wuScanStatus }
}

$pendingRebootText = $PendingReboot.PendingReboot
$adminModeText = if ($isAdmin) { "Yes" } else { "No" }

# =========================
# CSV Exports
# =========================

Write-Step "Saving CSV exports"

$csvFiles = @(
    @{ Name = "01_OS_Information.csv";            Data = $OsInfo },
    @{ Name = "02_Hardware_Summary.csv";          Data = $HardwareSummary },
    @{ Name = "03_Memory_Modules.csv";            Data = $MemoryModules },
    @{ Name = "04_Disk_Drives.csv";               Data = $DiskDrives },
    @{ Name = "05_Logical_Disks.csv";             Data = $LogicalDisks },
    @{ Name = "06_Network_Adapters.csv";          Data = $NetworkAdapters },
    @{ Name = "07_Video_Controllers.csv";         Data = $VideoControllers },
    @{ Name = "08_Printers.csv";                  Data = $Printers },
    @{ Name = "09_Installed_Applications.csv";    Data = $Apps },
    @{ Name = "10_Installed_Patches.csv";         Data = $InstalledPatches },
    @{ Name = "11_Missing_Patches.csv";           Data = $MissingPatches },
    @{ Name = "12_Windows_Update_Health.csv";     Data = $WindowsUpdateHealth },
    @{ Name = "13_Pending_Reboot.csv";            Data = $PendingReboot },
    @{ Name = "14_Antivirus_Products.csv";        Data = $AntivirusProducts },
    @{ Name = "15_Firewall_Profiles.csv";         Data = $FirewallProfiles },
    @{ Name = "16_BitLocker_Volumes.csv";         Data = $BitLockerVolumes },
    @{ Name = "17_Support_Services.csv";          Data = $ServiceAudit }
)

foreach ($file in $csvFiles) {
    $path = Join-Path $ReportFolder $file.Name

    if (@($file.Data).Count -gt 0) {
        $file.Data | Export-Csv -Path $path -NoTypeInformation -Encoding UTF8
    } else {
        Set-Content -Path $path -Value "" -Encoding UTF8
    }
}

Write-Ok "CSV files saved."

# =========================
# HTML Report
# =========================

Write-Step "Generating HTML report"

$summaryHtml = @"
<div class="summary">
    <div class="box"><span>Installed Apps</span><strong>$appCount</strong></div>
    <div class="box"><span>Installed Patches</span><strong>$installedPatchCount</strong></div>
    <div class="box"><span>Missing Updates</span><strong>$missingDisplay</strong></div>
    <div class="box"><span>Pending Reboot</span><strong>$pendingRebootText</strong></div>
    <div class="box"><span>Admin Mode</span><strong>$adminModeText</strong></div>
</div>
"@

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Bhima Tech IT Audit Report - $ComputerName</title>
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            font-family: Arial, Segoe UI, sans-serif;
            background: #f1f5f9;
            color: #0f172a;
        }
        header {
            background: linear-gradient(135deg, #0f172a, #1e3a8a, #1a56db);
            color: #ffffff;
            padding: 35px 25px;
        }
        header h1 {
            margin: 0 0 8px 0;
            font-size: 30px;
        }
        header p {
            margin: 4px 0;
            color: #cbd5e1;
        }
        main {
            max-width: 1400px;
            margin: 0 auto;
            padding: 25px;
        }
        .notice {
            background: #fffbeb;
            border: 1px solid #fcd34d;
            color: #92400e;
            padding: 15px 18px;
            border-radius: 10px;
            margin-bottom: 20px;
            line-height: 1.6;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }
        .box {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 4px 15px rgba(15, 23, 42, 0.05);
        }
        .box span {
            display: block;
            color: #64748b;
            font-size: 13px;
            margin-bottom: 8px;
        }
        .box strong {
            color: #0f172a;
            font-size: 26px;
        }
        .card {
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 22px;
            box-shadow: 0 4px 15px rgba(15, 23, 42, 0.05);
        }
        .card h2 {
            margin: 0 0 15px 0;
            font-size: 20px;
            color: #0f172a;
            border-left: 5px solid #06b6d4;
            padding-left: 12px;
        }
        .table-wrap {
            overflow-x: auto;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }
        th {
            background: #0f172a;
            color: #ffffff;
            text-align: left;
            padding: 10px;
            white-space: nowrap;
        }
        td {
            border-bottom: 1px solid #e2e8f0;
            padding: 9px 10px;
            vertical-align: top;
            word-break: break-word;
            max-width: 420px;
        }
        tr:nth-child(even) td {
            background: #f8fafc;
        }
        tr:hover td {
            background: #ecfeff;
        }
        .empty {
            color: #64748b;
            font-style: italic;
        }
        ul {
            line-height: 1.8;
        }
        footer {
            text-align: center;
            color: #64748b;
            font-size: 12px;
            padding: 25px;
        }
        @media print {
            body { background: #ffffff; }
            .card, .box { box-shadow: none; }
            .table-wrap { overflow: visible; }
        }
    </style>
</head>
<body>
    <header>
        <h1>BHIMA TECH IT SUPPORT</h1>
        <h2>Windows Endpoint Audit Report</h2>
        <p><strong>Computer:</strong> $ComputerName</p>
        <p><strong>Generated On:</strong> $($GeneratedOn.ToString("dd-MMM-yyyy hh:mm:ss tt"))</p>
        <p><strong>Report Type:</strong> Read-only Local IT Assessment</p>
    </header>

    <main>
        <div class="notice">
            <strong>Confidential:</strong> This report contains endpoint inventory details such as computer name, serial number, IP addresses, installed software, patch status, and basic security status.
            It was generated locally on this computer and is not uploaded anywhere by this script.
            If Windows Update missing-patch scanning was enabled, the scan may contact Microsoft Update or the configured WSUS server.
        </div>

        $summaryHtml

        $(New-HtmlTableSection -Title "1. Windows / OS Information" -Data $OsInfo)
        $(New-HtmlTableSection -Title "2. Hardware Summary" -Data $HardwareSummary)
        $(New-HtmlTableSection -Title "3. Memory / RAM Modules" -Data $MemoryModules)
        $(New-HtmlTableSection -Title "4. Physical Disk Drives" -Data $DiskDrives)
        $(New-HtmlTableSection -Title "5. Logical Drives / Free Space" -Data $LogicalDisks)
        $(New-HtmlTableSection -Title "6. Network Adapters / IP Details" -Data $NetworkAdapters)
        $(New-HtmlTableSection -Title "7. Video / Display Controllers" -Data $VideoControllers)
        $(New-HtmlTableSection -Title "8. Printer Inventory" -Data $Printers)
        $(New-HtmlTableSection -Title "9. Installed Applications" -Data $Apps)
        $(New-HtmlTableSection -Title "10. Installed Windows Patches / Hotfixes" -Data $InstalledPatches)
        $(New-HtmlTableSection -Title "11. Missing / Available Windows Updates" -Data $MissingPatches)
        $(New-HtmlTableSection -Title "12. Windows Update Health" -Data $WindowsUpdateHealth)
        $(New-HtmlTableSection -Title "13. Pending Reboot Status" -Data $PendingReboot)
        $(New-HtmlTableSection -Title "14. Antivirus Products" -Data $AntivirusProducts)
        $(New-HtmlTableSection -Title "15. Firewall Profiles" -Data $FirewallProfiles)
        $(New-HtmlTableSection -Title "16. BitLocker Volumes" -Data $BitLockerVolumes)
        $(New-HtmlTableSection -Title "17. Support-Related Windows Services" -Data $ServiceAudit)

        <section class="card">
            <h2>18. Important Notes</h2>
            <ul>
                <li>This script is intended for authorized IT audit, troubleshooting, and documentation purposes only.</li>
                <li>Missing updates are the updates currently offered by Windows Update, Microsoft Update, or the configured WSUS server.</li>
                <li>This report is not a formal vulnerability assessment, compliance certificate, or regulatory audit.</li>
                <li>Some security sections may show no data if the feature is unavailable, the system is not domain-managed, or the script is not run as Administrator.</li>
                <li>For client reports, review the HTML/CSV files before sharing and remove any sensitive details if required.</li>
            </ul>
        </section>
    </main>

    <footer>
        Bhima Tech IT Support | Generated by BhimaTech-IT-Audit.ps1 | All product names and trademarks belong to their respective owners.
    </footer>
</body>
</html>
"@

$html | Set-Content -Path $HtmlReport -Encoding UTF8

Write-Ok "HTML report generated."

# =========================
# Open Report & Console Summary
# =========================

try {
    Start-Process -FilePath $HtmlReport
    Write-Ok "HTML report opened in your default browser."
} catch {
    Write-WarnMsg "Could not open the report automatically. Please open this file manually:"
    Write-Host $HtmlReport -ForegroundColor Yellow
}

Write-Step "AUDIT SUMMARY"

Write-Host "Computer Name       : $ComputerName" -ForegroundColor White
Write-Host "Windows             : $($OsInfo.WindowsProductName)" -ForegroundColor White
Write-Host "Version / Build     : $($OsInfo.WindowsVersion) / $($OsInfo.FullBuild)" -ForegroundColor White
Write-Host "Manufacturer/Model  : $($HardwareSummary.Manufacturer) $($HardwareSummary.Model)" -ForegroundColor White
Write-Host "Installed Apps      : $appCount" -ForegroundColor White
Write-Host "Installed Patches   : $installedPatchCount" -ForegroundColor White
Write-Host "Missing Updates     : $missingDisplay" -ForegroundColor White
Write-Host "Pending Reboot      : $pendingRebootText" -ForegroundColor White
Write-Host "Report Folder       : $ReportFolder" -ForegroundColor Green
Write-Host "HTML Report         : $HtmlReport" -ForegroundColor Green

Write-Host "`nNote: If Windows Update scan hangs, run again with -SkipWindowsUpdate." -ForegroundColor Yellow

if (-not $NoPause -and [Environment]::UserInteractive) {
    Write-Host "`nPress Enter to exit..." -ForegroundColor Gray
    Read-Host | Out-Null
}
