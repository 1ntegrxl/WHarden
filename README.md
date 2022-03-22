# Windows Hardening Script

```
██╗    ██╗██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗
██║    ██║██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║
██║ █╗ ██║███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║
██║███╗██║██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║
╚███╔███╔╝██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
```

A Windows 10 powershell hardening script.

This scripts tries to harden a Windows 10 server or Workstation. Use with care. Please check the applications that are being removed inside the script before running the script.


## Usage

Open powershell on your Windows machine (make sure you have administrative rights) and launch the powershell script.

```
PS C:\tmp> ./WHarden.ps1 -Help

WHarden - Version 1.0 


Usage : ./WHarden.ps1 [options]
-Type	        Specify the type of hardening you want to do ("Security","Telemetry","all")
-SaveRestore	This option saves a restore point before doing optimizations 
-Restore	   When a Restore point has been created with -SaveRestore, this option helps the user to apply that save.

Examples : 

    ./WHarden.ps1 -Type Security -CreateRestore
    ./Wharden.ps1 -Type all
```

To apply all recommended optimizations You can use the following command for example : 

``` 
PS C:\tmp> ./WHarden.ps1 -Type all

██╗    ██╗██╗  ██╗ █████╗ ██████╗ ██████╗ ███████╗███╗   ██╗
██║    ██║██║  ██║██╔══██╗██╔══██╗██╔══██╗██╔════╝████╗  ██║
██║ █╗ ██║███████║███████║██████╔╝██║  ██║█████╗  ██╔██╗ ██║
██║███╗██║██╔══██║██╔══██║██╔══██╗██║  ██║██╔══╝  ██║╚██╗██║
╚███╔███╔╝██║  ██║██║  ██║██║  ██║██████╔╝███████╗██║ ╚████║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═══╝
 

 The Windows 10 Hardening script  --- (Use with care)

 This script is intended to harden your system. It includes Bloatware removal, security optimizations and telemetry removal.
 Use -Help to display WHarden help.

 [..]

 [+] Toutes les phases de hardening ont été appliqué !
 ```
You can use the `-CreateRestore` option to create a Windows restore point before hardening your system in case something goes wrong.


## TODO 

- Dynamicaly detect Office version and apply optimizations related to that version.



