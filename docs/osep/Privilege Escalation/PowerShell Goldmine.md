### **PowerShell Goldmine (logs)**

**Command History**

```powershell
Get-History

```

**Finding PSReadline History File Path**

```powershell
(Get-PSReadlineOption).HistorySavePath

```

**Finding and Viewing the Goldmine for All User (Script)**

```powershell
$userProfiles = Get-ChildItem -Path C:\Users -Directory

foreach ($profile in $userProfiles) {
    $historyPath = Join-Path -Path $profile.FullName -ChildPath "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"

    if (Test-Path $historyPath) {
        Write-Output "User: $($profile.Name)"
        Write-Output "PSReadline History Path: $historyPath"
        Write-Output "--------------------------------"
        Get-Content -Path $historyPath
        Write-Output ""
    }
}

```
