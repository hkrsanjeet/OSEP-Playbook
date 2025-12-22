### **Enumeration**

| **Category** | **Command** | **Description** |
| --- | --- | --- |
| **Username and Hostname** | `whoami` | Displays the current user and hostname. |
| **Existing Users** | `Get-LocalUser` | Lists all local users. |
| **Existing Groups** | `Get-LocalGroup` | Lists all local groups. |
|  | `net localgroup` | Alternative method to list groups. |
|  | `Get-LocalGroupMember -GroupName [GroupName]` | Lists members of a specific group. |
| **Operating System, Version, and Architecture** | `systeminfo` | Displays detailed OS information. |
| **Network Information** | `ipconfig /all` | Displays detailed network configuration. |
|  | `route print` | Shows routing table. |
|  | `netstat -ano` | Displays network connections and listening ports. |
| **Installed Applications** | **32-bit Applications:** `Get-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"` | Lists installed 32-bit applications. |
|  | *Optional:* `Select-Object -Property DisplayName` | Filters to show only application names. |
|  | **64-bit Applications:** `Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"` | Lists installed 64-bit applications. |
|  | *Optional:* `Select-Object -Property DisplayName` | Filters to show only application names. |
| **Running Processes** | `Get-Process` | Lists all running processes. |
|  | *Optional:* `Select-Object -Property ProcessName, Path` | Displays process names and paths. |
| **Service Accounts** | `Get-WmiObject -Class Win32_Service | Select-Object Name, StartName` | Lists services and their associated accounts. |
| **Scheduled Tasks** | `Get-ScheduledTask | Select-Object TaskName, TaskPath, State` | Displays scheduled tasks and their status. |
| **Local Administrator Group Members** | `Get-LocalGroupMember -GroupName "Administrators"` | Lists members of the local Administrators group. |
| **System Drives and Mounted Volumes** | `Get-PSDrive -PSProvider FileSystem` | Shows all drives and mounted volumes, including network shares. |
| **PowerShell Version** | `$PSVersionTable.PSVersion` | Displays the version of PowerShell in use, which can be relevant for identifying potential exploitability or compatibility issues. |
