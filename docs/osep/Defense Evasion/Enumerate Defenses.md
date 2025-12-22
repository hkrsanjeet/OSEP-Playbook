### **Enumerate Defenses**

- **Get AppLocker State**

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

```

- **Get AMSI State**

```powershell
# CMD
reg query "HKLM\Software\Microsoft\AMSI"
# 0 = disabled
# 1 (or exist but is missing) = enabled

# PowerShell
'amsiutils'

# Alternative
Get-Process -Name powershell | ForEach-Object { $_.Modules | Where-Object { $_.ModuleName -eq "amsi.dll" } }
# If amsi.dll is loaded then AMSI is active
# If not AMSI is disabled or bypassed

```

- **Check if Defender is Working**

```powershell
Get-MpComputerStatus | Select-Object AMRunningMode, AntivirusEnabled

Get-MpComputerStatus

```

- **Get CLM State**

```powershell
$ExecutionContext.SessionState.LanguageMode

# FullLanguaje: allows all cmdlets and entire .NET Framework
# RestrictedLanguage allows default cmdlets but heavily restricts everything else
# NoLanguage: disables all script text

```

- **Get PPL (Protected Processes Light) State**

```powershell
Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Lsa -Name "RunAsPPL"

```
