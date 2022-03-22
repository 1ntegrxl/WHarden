<#

.DESCRIPTION

This scripts tries to harden a Windows 10 server or Workstation. Use with care. Please check the applications that are being removed inside the script

.PARAMETER Type

Type of actions you want to perform on the target machine (Security,All,Privacy,Bloatware).

.PARAMETER Test

This option simulates the changes before applying them. 

.PARAMETER RestoreState 

When a Restore point has been created, this option helps the user to apply that save.

.PARAMETER SaveRestore

Save a restore point before doing the optimizations.

.EXAMPLE

WHarden.ps1 -Type all  
WHarden.ps1 -Type Telemetry -SaveRestore 
WHarden.ps1 -Restore

.NOTES
This script attempts to make your system more secure and hardened. However, please bear in mind that it may remove applications that you may be using, please verify the apps and services that are removed by the script.

.LINK

https://gitlab.offsec.local/messaoudin/Windows-hardening-script

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

Function DisableServices {
	Write-Warning '[+] Désactivation des services Windows '
	[Array]$Services =
		'lmhosts', # TCP/IP NetBIOS Helper
		'wlidsvc', # Microsoft Account Sign-in Assistant
		'SEMgrSvc', # Payments NFC/SE Manager
		'tzautoupdate', # Auto Time Zone Updater
		'AppVClient', # Microsoft App-V Client
		'RemoteRegistry', # Remote Registry
		'RemoteAccess', # Routing & Remote Access
		'shpamsvc', # Shared PC Account Manager
		'UevAgentService', # User Experience Virtualization Service
		'WdiServiceHost', # Diagnostic Service Host
		'WdiSystemHost', # Diagnostic System Host
		'ALG', # Application Layer Gateway
		'PeerDistSvc', # BranchCache
		'Eaphost', # Extensible Authentication Protocol
		'fdPHost', # Function Discovery Provider Host
		'LxpSvc', # Language Experience Service
		'lltdsvc', # Link-Layer Topology Discovery Mapper
		'diagnosticshub.standardcollector.service', # Microsoft (R) Diagnostics Hub Standard Collector Service
		'MSiSCSI', # Microsoft iSCSI Initiator Service
		'WpcMonSvc', # WpcMonSvc
		'PNRPsvc', # Peer Name Resolution Protocol
		'p2psvc', # Peer Networking Grouping
		'p2pimsvc', # Peer Networking Identity Manager
		'PerfHost', # Performance Counter DLL Host
		'pla', # Performance Logs & Alerts
		'PNRPAutoReg', # PNRP Machine Name Publication
		'PrintNotify', # PrintNotify
		'wercplsupport', # Problem Reports & Solutions Control Panel
		'TroubleshootingSvc', # Recommended Troubleshooting Service
		#'SessionEnv', # Remote Desktop Configuration
		#'TermService', # Remote Desktop Service
		#'UmRdpService', # Remote Desktop Services UserMode Port Redirector
		'RpcLocator', # Remote Procedure Call (RPC) Locator
		'RetailDemo', # Retail Demo Service
		'SCPolicySvc', # Smart Card Removal PolicyDisplayHelpBanner
		'SharedRealitySvc', # Spatial Data Service
		'WiaRpc', # Still Image Acquisition Events
		'VacSvc', # Volumetric Audio Compositor Service
		'WalletService', # WalletService
		'wcncsvc', # Windows Connect Now
		'Wecsvc', # Windows Event Collector
		'perceptionsimulation', # Windows Perception Simulation Service
		'WinRM', # Windows Remote Management (WS-Management)
		'wmiApSrv', # WMI Performance Adapter
		'WwanSvc', # WWAN AutoConfig
		'XblAuthManager', # Xbox Live Auth Manager
		'XboxNetApiSvc', # Xbox Live Networking Service
		'RasAuto', # Remote Access Auto Connection Manager
		'XblGameSave', # Xbox Live Game Save
		'XboxGipSvc', # Xbox Accessory Management
		'PushToInstall', # Windows PushToInstall Service
		'spectrum', # Windows Perception Service
		'icssvc', # Windows Mobile Hotspot Service
		'wisvc', # Windows Insider Service
		'WerSvc', # Windows Error Reporting Service
		'FrameServer', # Windows Camera Frame Service
		'WFDSConMgrSvc', # Wi-Fi Direct Services Connection Manager Service
		'ScDeviceEnum', # Smart Card Device Enumeration Service
		'SCardSvr', # Smart Card
		'PhoneSvc', # Phone Service
		'IpxlatCfgSvc', # IP Translation Configuration Service
		'SharedAccess', # Internet Connection Sharing (ICS)
		'vmicvss', # Hyper-V Volume Shadow Copy Requestor
		'vmictimesync', # Hyper-V TIme Synchronization Service
		'vmicrdv', # Hyper-V Remote Desktop Virtualization Service
		'vmicvmsession', # Hyper-V PowerShell Direct Service
		'vmicheartbeat', # Hyper-V Heartbeat Service
		'vmicshutdown', # Hyper-V Guest Shudown Service
		'vmicguestinterface', # Hyper-V Guest Service Interface
		'vmickvpexchange', # Hyper-V Data Exchange Service
		'HvHost', # HV Host Service
		'FDResPub', # Function Discovery Resource Publication
		'diagsvc', # Diagnostic Execution Service
		'autotimesvc', # Cellular Time
		'bthserv', # Bluetooth Support Service
		'BTAGService', # Bluetooth Audio Gateway Service
		'AssignedAccessManagerSvc', # AssignedAccessManager Service
		'AJRouter', # AllJoyn Router Service
		'lfsvc', # Geolocation Service
		'CDPSvc', # Connected Devices Platform Service
		'DiagTrack', # Connected User Experiences and Telemetry
		'DPS', # Diagnostic Policy Service
		'iphlpsvc', # IP Helper
		'RasMan', # Remote Access Connection Manager
		'SstpSvc', # Secure Socket Tunneling Protocol Service
		'ShellHWDetection', # Shell Hardware Detection
		'SSDPSRV', # SSDP Discovery
		'WbioSrvc', # Windows Biometric Service
		'stisvc' # Windows Image Acquisition (WIA)

	Foreach ($Service in $Services) {
		Set-Service -Name $Service -StartupType 'Disabled'
		Stop-Service -Name $Service -Force
	}
	Write-Host '[+] Tous les services ont été arrêtés avec succès'
}

Function DeleteApps {
	Write-Warning "[+] Suppression d'applications inutiles "
	[Array] $Apps = 
	'3DBuilder',
	'Cortana',
    'Getstarted' ,
    'WindowsAlarms',
	'WindowsCamera',
	'bing',
	'MicrosoftOfficeHub',
	'OneNote',
	'people',
	'WindowsPhone',
	'photos',
	'SkypeApp',
	'solit',
	'WindowsSoundRecorder',
	'xbox',
	'windowscommunicationsapps',
	'zune',
	'WindowsCalculator'
	'WindowsMaps',
	'windowscommunicationsapps'

	Foreach ($App in $Apps) { 
		Get-AppxPackage $App | Remove-AppxPackage
		Write-Host "[+] $App a été supprimé avec succès"
	}
}
	
Function DisableTelemetry {
        Write-Output "[+] Désactivation la Télémetrie..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -Type DWord -Value 1
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -Type DWord -Value 1
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -Type DWord -Value 0
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -Type DWord -Value 1
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value 0
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
        Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
}

Function MacroKill {
	Write-Ouptut "[+] Ajout d'options Office anti-macro"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\access\security" -Name "vbawarnings" -Type DWord -Value 4 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" -Name "vbawarnings" -Type DWord -Value 4 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" -Name "excelbypassencryptedmacroscan" -Type DWord -Value 0 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" -Name "vbawarnings" -Type DWord -Value 4 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\ms project\security" -Name "level" -Type DWord -Value 4 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" -Name "level" -Type DWord -Value 4 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" -Name"vbawarnings" -Type DWord -Value 4 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\publisher\security" -Name "vbawarnings" -Type DWord -Value 4 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" -Name "vbawarnings" -Type DWord -Value 4 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\visio\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value1 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -Name "vbawarnings" -Type DWord -Value 4 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -Name "blockcontentexecutionfrominternet" -Type DWord -Value 1 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\word\security" -Name "wordbypassencryptedmacroscan" -Type DWord -Value 0 
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\common\security" -Name "automationsecurity" -Type DWord -Value 3 
}

Function Disablesmbv1 {
	Write-output "[+] Désactivation de smbv1"
	try {
		Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol
	} catch {
		Write-Output "[-] SMBv1 est déjà désactivé !"
	}
}

Function DisableNCSIProbe {
        Write-Output "[+] Désactivation des tests de connectivité"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" -Name "NoActiveProbe" -Type DWord -Value 1
}

Function DisableConnectionSharing {
        Write-Output "[+] Désactivation du partage de connexion Windows..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -Type DWord -Value 0
}

Function EnableDotNetStrongCrypto {
        Write-output "[+] Activation de l'encodage .NET avancé ..."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
}

Function EnableMeltdownCompatFlag {
        Write-Output "[+] Activation du Flag de compatibilite Meltdown (CVE-2017-5754)..."
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat")) {
                New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\QualityCompat" -Name "cadca5fe-87d3-4b96-b7fb-a231484277cc" -Type DWord -Value 0
}

Function EnableUpdateMSRT {
        Write-Output "[+] Activation du programme de suppression de menace Windows..."
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
}

Function EnableAutoRebootOnCrash {
        Write-Output "[+] Activation du auto-reboot après un crash (BSOD)..."
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" -Name "AutoReboot" -Type DWord -Value 1
}

Function EnableCIMemoryIntegrity {
        Write-Output "[+] Activation des protections mémoires "
        If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity")) {
                New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Type DWord -Value 1
}

Function DisableDefenderCloud {
        Write-Output "[+] Désactivation de Windows Defender Cloud..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -Type DWord -Value 0
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -Type DWord -Value 2
}

Function DisableLocation {
        Write-Output "[+] Désactivation du service de localisation..."
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
        }
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -Type DWord -Value 1
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -Type DWord -Value 1
}

Function ActivatePUAProtection {
	Set-MpPreference -PUAProtection Enabled
	Write-Output "[+] Activation de la protection PUA"
}

Function CreateRestorePoint {
	Checkpoint-Computer -Description "ChangeNetSettings" -RestorePointType MODIFY_SETTINGS
	Write-Ouptut "[+] Un point de restauration a été créé avec succès"
}

Function RestoreFromRestorePoint($restoreID) {
	Restore-Cowmputer -RestorePoint $restoreId -Confirm
	sleep 1
}

Function Optimize_all {
	CreateRestorePoint
	DisableServices
	DisableTelemetry
	DeleteApps
	#MacroKill # Disabled temporarily  
	Disablesmbv1
	DisableNCSIProbe
	DisableConnectionSharing
	EnableDotNetStrongCrypto
	EnableMeltdownCompatFlag
	EnableUpdateMSRT
	EnableAutoRebootOnCrash
	EnableCIMemoryIntegrity
	DisableDefenderCloud
	DisableLocation
	ActivatePUAProtection

}

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
 This script is intended to harden your system. It includes Bloatware removal, security optimizations and telemetry removal.
 Use -Help to display WHarden help. 
"@
	Write-Output $banner
}

Function DisplayHelpBanner {
	$help = @"
WHarden -- Version 1.0 `n`n
Usage : ./WHarden.ps1 [options]`n
-Type			Specify the type of hardening you want to do ("Security","Telemetry","all")
-SaveRestore		This option saves a restore point before doing optimizations 
-Restore		When a Restore point has been created with -SaveRestore, this option helps the user to apply that save.`n
Examples : 

./WHarden.ps1 -Type Security -CreateRestore
./Wharden.ps1 -Type all
"@
	Write-Output $help
}

	
Clear-host
DisplayBanner
$MachineInformation = Get-ComputerInfo
$Username = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$WinSystemLocale = Get-WinSystemLocale
$RunasAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator') 

$Message = @"
[**] System information : `n
[*] Hostname: $MachineInformation.CsDNSHostName `n
[*] Username: $Username `n
[*] Domain: $MachineInformation.CsDomain `n
[*] Windows version: $MachineInformation.WindowsVersion `n
[*] Windows build: $MachineInformation.WindowsBuildLabEx `n
[*] System-locale: $WinSystemLocale.Name `n
[*] Powershell Version: $PowerShellVersion `n
"@

If (-not($RunasAdmin)) {

	Write-Output "[+] Script lancé en tant qu'administrateur.."
	if ($Restore){
		RestoreFromRestorePoint
		exit
	}
	if ($Help) {
		DisplayHelpBanner
		exit
	}
	if ($SaveRestore) {
		CreateRestorePoint
	}
	Switch ($Type)
	{
		"All" {
			Write-Output "[*] Phases de hardening commencées ..." 
			optimize_all 
			Write-Output "[+] Toutes les phases de hardening ont été appliqué !"
		}
		"Privacy" {
			Write-Host "[+] Application des paramètres de vie privée ..."
			DisableTelemetry
			DisableLocation
			DisableDefenderCloud
			DisableNCSIProbe
			Write-host "[+] Application des paramètres de vie privée terminée !"
		}
		"Security" {
			Write-host "[+] Application des paramètres de sécurité ..."
			DisableConnectionSharing
			EnableDotNetStrongCrypto
			EnableMeltdownCompatFlag
			EnableUpdateMSRT
			EnableAutoRebootOnCrash
			EnableCIMemoryIntegrity
			ActivatePUAProtection
			Write-Host "[+] Application des paramètres de sécurité terminée !"
		}
		"Bloatware" {
			DeleteApps
			DisableServices
		}
		default {
			DisplayHelpBanner
		}
	}
	
}
else {
	Write-Output "[-] Veuillez lancer le script en tant qu'administrateur !"
}
