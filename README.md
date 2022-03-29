# Windows Hardening Script

**WHarden** is a PowerShell script designed to harden Windows 10 systems by applying security optimizations, privacy settings, and removing bloatware. The script should be used with caution. Ensure to review which applications are removed or altered before running.

### Features:
- **Security Optimizations**: Apply system security improvements.
- **Privacy Settings**: Disable telemetry, location, and other privacy-invasive settings.
- **Bloatware Removal**: Clean up unnecessary apps and services.

### Prerequisites:
- Administrative rights are required to run the script.

### Usage:

Open PowerShell as Administrator, navigate to the script’s directory, and execute the following:

```powershell
PS C:\tmp> ./WHarden.ps1 -Help
```

#### Arguments:
- `-Type <Security|Privacy|All>`: Define the optimization type.
- `-SaveRestore`: Create a system restore point before hardening.
- `-Restore`: Revert to a restore point created with `-SaveRestore`.
- `-Help`: Display the help information.

#### Example Commands:
1. **Apply all optimizations:**
   ```powershell
   PS C:\tmp> ./WHarden.ps1 -Type All
   ```

2. **Apply security optimizations only:**
   ```powershell
   PS C:\tmp> ./WHarden.ps1 -Type Security
   ```

3. **Restore system from a previously created restore point:**
   ```powershell
   PS C:\tmp> ./WHarden.ps1 -Restore
   ```

### Main Functionality:

The script applies several important optimizations for security and privacy. Here is the logic that is followed when the script is executed:

1. **Check if Run as Admin**: If the script is not run as administrator, it will display a warning.
2. **Create Restore Point**: If `-SaveRestore` is specified, the script creates a restore point before making any changes.
3. **Execute Based on Type**: Based on the `-Type` argument, the script will apply various optimizations:
   - **All**: Applies all security and privacy optimizations.
   - **Security**: Focuses on security optimizations (like disabling connection sharing, enabling strong crypto, etc.).
   - **Privacy**: Focuses on privacy settings (disabling telemetry, location, etc.).

### Known Issues & TODO:
- Detect Office version dynamically to apply optimizations specific to it.
- Additional system hardening options may be added in the future.

### Disclaimer:
- The script should be tested in a controlled environment before using it on production systems.
- The script makes significant changes to your system, including the removal of unnecessary apps and services, which might affect system functionality.
