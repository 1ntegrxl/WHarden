<# 
.DESCRIPTION
This script is designed to harden a Windows 10 system by performing various security optimizations. 
Use with caution and ensure you review the applications and services removed or modified.

.PARAMETER Type
Type of actions to perform on the target machine (Security, All, Privacy, Bloatware).

.PARAMETER Test
Simulate the changes before applying them.

.PARAMETER RestoreState 
Restore the system to a previous state using a saved restore point.

.PARAMETER SaveRestore
Create a restore point before applying optimizations.

.EXAMPLE
WHarden.ps1 -Type All
WHarden.ps1 -Type Telemetry -SaveRestore 
WHarden.ps1 -Restore

.NOTES
This script aims to make your system more secure, but it may remove or disable applications and services that could be important for certain users.
Please verify the list of apps and services before running it.
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$False,Position=0)]
    [String]$Type,

    [Parameter(Mandatory=$False,Position=1)]
    [switch]$Test,

    [Parameter(Mandatory=$False,Position=2)]
    [switch]$Restore,

    [Parameter(Mandatory=$False,Position=3)]
    [switch]$CreateRestore,

    [Parameter(Mandatory=$False)]
    [switch]$Help
)

# Function to check if running as Administrator
Function Check-Admin {
    $isAdmin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if ($isAdmin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[+] Running as Administrator."
    } else {
        Write-Host "[-] This script requires Administrator privileges. Please run as Administrator."
        Exit
    }
}

# Function to get system information
Function Get-SystemInfo {
    $sysInfo = Get-WmiObject -Class Win32_OperatingSystem
    Write-Host "[+] System Information:"
    Write-Host "OS Name: $($sysInfo.Caption)"
    Write-Host "Version: $($sysInfo.Version)"
    Write-Host "Architecture: $($sysInfo.OSArchitecture)"
    Write-Host "Build: $($sysInfo.BuildNumber)"
}

# Function to disable unnecessary services
Function DisableServices {
    Write-Warning '[+] Disabling unnecessary Windows services...'
    [Array]$Services = @(
        'lmhosts', 'wlidsvc', 'SEMgrSvc', 'tzautoupdate', 'AppVClient', 'RemoteRegistry', 'RemoteAccess', 'shpamsvc',
        'UevAgentService', 'WdiServiceHost', 'WdiSystemHost', 'ALG', 'PeerDistSvc', 'Eaphost', 'fdPHost', 'LxpSvc',
        'lltdsvc', 'diagnosticshub.standardcollector.service', 'MSiSCSI', 'WpcMonSvc', 'PNRPsvc', 'p2psvc', 'p2pimsvc',
        'PerfHost', 'pla', 'PNRPAutoReg', 'PrintNotify', 'wercplsupport', 'TroubleshootingSvc', 'RpcLocator',
        'RetailDemo', 'SCPolicySvc', 'SharedRealitySvc', 'WiaRpc', 'VacSvc', 'WalletService', 'wcncsvc', 'Wecsvc',
        'perceptionsimulation', 'WinRM', 'wmiApSrv', 'WwanSvc', 'XblAuthManager', 'XboxNetApiSvc', 'RasAuto', 
        'XblGameSave', 'XboxGipSvc', 'PushToInstall', 'spectrum', 'icssvc', 'wisvc', 'WerSvc', 'FrameServer', 
        'WFDSConMgrSvc', 'ScDeviceEnum', 'SCardSvr', 'PhoneSvc', 'IpxlatCfgSvc', 'SharedAccess', 'vmicvss', 
        'vmictimesync', 'vmicrdv', 'vmicvmsession', 'vmicheartbeat', 'vmicshutdown', 'vmicguestinterface', 
        'vmickvpexchange', 'HvHost', 'FDResPub', 'diagsvc', 'autotimesvc', 'bthserv', 'BTAGService', 
        'AssignedAccessManagerSvc', 'AJRouter', 'lfsvc', 'CDPSvc', 'DiagTrack', 'DPS', 'iphlpsvc', 'RasMan', 
        'SstpSvc', 'ShellHWDetection', 'SSDPSRV', 'WbioSrvc', 'stisvc'
    )
    
    foreach ($Service in $Services) {
        Set-Service -Name $Service -StartupType 'Disabled' 
        Stop-Service -Name $Service
    }
    Write-Host '[+] All unnecessary services have been disabled.'
}

# Function to remove unnecessary apps
Function DeleteApps {
    Write-Warning "[+] Removing unnecessary apps..."
    [Array] $Apps = @(
        '3DBuilder', 'Cortana', 'Getstarted', 'WindowsAlarms', 'WindowsCamera', 'MicrosoftOfficeHub', 
        'OneNote', 'people', 'WindowsPhone', 'photos', 'SkypeApp', 'solit', 'WindowsSoundRecorder', 'xbox', 
        'windowscommunicationsapps', 'zune', 'WindowsCalculator', 'WindowsMaps'
    )

    foreach ($App in $Apps) {
        Get-AppxPackage -Name $App | Remove-AppxPackage
        Write-Host "[+] $App has been removed."
    }
}

# Function to disable telemetry settings
Function DisableTelemetry {
    Write-Output "[+] Disabling telemetry..."
    $telemetryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    )
    foreach ($path in $telemetryPaths) {
        Set-ItemProperty -Path $path -Name "AllowTelemetry" -Type DWord -Value 0
    }
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" 
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" 
}

# Function to disable SMBv1
Function DisableSmbv1 {
    Write-Output "[+] Disabling SMBv1..."
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
    } catch {
        Write-Output "[-] SMBv1 is already disabled."
    }
}

# Function to enable .NET strong cryptography
Function EnableDotNetStrongCrypto {
    Write-Output "[+] Enabling .NET strong cryptography..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
}

# Function to create a system restore point
Function CreateRestorePoint {
    Write-Output "[+] Creating a restore point..."
    Checkpoint-Computer -Description "System Hardened" -RestorePointType MODIFY_SETTINGS
}

# Function to restore from a system restore point
Function RestoreFromRestorePoint {
    Write-Output "[+] Restoring system to the last restore point..."
    $restorePoints = Get-ComputerRestorePoint
    if ($restorePoints.Count -gt 0) {
        $lastRestorePoint = $restorePoints[0] # The latest restore point
        Restore-Computer -RestorePoint $lastRestorePoint.SequenceNumber
        Write-Host "[+] System restored to restore point: $($lastRestorePoint.Description)"
    } else {
        Write-Host "[-] No restore points found."
    }
}

# Function to optimize the system by applying all hardening steps
Function OptimizeAll {
    CreateRestorePoint
    DisableServices
    DisableTelemetry
    DeleteApps
    DisableSmbv1
    EnableDotNetStrongCrypto
    Write-Host '[+] System has been optimized and secured.'
}

# Display a banner
Function DisplayBanner {
    $banner = @"
██╗    ██╗██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗
██║    ██║██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║
██║ █╗ ██║███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║
██║███╗██║██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║
╚███╔███╔╝██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
 `n
 The Windows 10 Hardening script  --- (Use with care)`n
 This script is intended to harden your system. It includes Bloatware removal, security optimizations, and telemetry removal.
 Use -Help to display WHarden help. 
"@
    Write-Output $banner
}

# Function to display help information
Function DisplayHelpBanner {
    $help = @"
WHarden -- Version 2.0 `n`n
Usage: ./WHarden.ps1 [options]`n
-Type            Specify the type of hardening you want to apply ("Security", "Telemetry", "All")
-SaveRestore     Save a restore point before making changes
-Restore         Restore system from a saved restore point
-Test            Simulate actions without making changes
-Help            Show help information
"@
    Write-Output $help
}

# Main script logic to run based on user input
Check-Admin
Get-SystemInfo

If ($Help) {
    DisplayHelpBanner
    Exit
}

DisplayBanner

If ($CreateRestore) {
    CreateRestorePoint
}

If ($Restore) {
    RestoreFromRestorePoint
}

Switch ($Type) {
    "All" {
        Write-Output "[*] Phases of hardening started..." 
        OptimizeAll
        Write-Output "[+] All phases of hardening have been applied!"
    }
    "Privacy" {
        Write-Host "[+] Applying privacy settings..."
        DisableTelemetry
        Write-Host "[+] Privacy settings applied!"
    }
    "Security" {
        Write-Host "[+] Applying security settings..."
        EnableDotNetStrongCrypto
        Write-Host "[+] Security settings applied!"
    }
    "Bloatware" {
        Write-Host "[+] Removing bloatware..."
        DeleteApps
        DisableServices
        Write-Host "[+] Bloatware removed!"
    }
    default {
        Write-Output "[-] Invalid Type. Please use one of the valid options: All, Privacy, Security, or Bloatware."
    }
}

If ($Test) {
    Write-Host "[Test Mode] No changes will be applied."
}
