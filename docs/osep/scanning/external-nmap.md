---
title: External Scanning - Nmap
sidebar_position: 1
---



### Advanced enumeration
#### Complete system and version detection 

```bash
nmap -A [IP/domain] -oN [machine_name].txt
```
### Fast all-ports scan 
#### Combines SYN and UDP scans for speed
```bash
sudo nmap -p- -sS -sU --min-rate=1000 --max-retries=1 -T4 [IP/Domain]
```
### Fast scan alternative   
#### TCP only; skips host discovery for speed 
```bash
nmap -p- -T4 -n -Pn [IP/domain] -oN [machine_name]_ports.txt
```
### Fast scan second alternative
#### Increases min rate for quicker scanning
```bash
sudo nmap --min-rate=5000 -p- -vvv -Pn -n -oG openPorts.txt [IP]
```
### Discovery all ports scan
#### For full port discovery
```bash
nmap -p- [IP/Domain] -oN [machine_name]_ports.txt
```
### Top ports
#### Scan common ports only
```bash
nmap [IP/Domain] --top-ports [number_of_top_ports]
```
 
