**Good folders to check for things are the web root folders, either Windows or Linux, for example in Windows (C:\inetpub\wwwroot) some config files could have hardcoded strings in: `/Temp`, `/Tasks`, or `/Config` folders**

**Enumerating Everything the Users Folder Has**

```powershell
Get-ChildItem -Path C:\Users\ -Include *.* -File -Recurse -ErrorAction SilentlyContinue

```

**Searching for Password Manager Databases**

```powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue

```

**Searching for Sensitive Information in the XAMPP Directory**

```powershell
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue

```

**Finding Unusual Files and Directories**

```powershell
Get-ChildItem -Path C:\Users -Include *.bak,*.old,*.tmp -File -Recurse -ErrorAction SilentlyContinue

```

**Finding files with SYSTEM or Administrators group permissions**

```powershell
Get-ChildItem -Path [Path] -File -Recurse | Where-Object {
    (Get-Acl $_.FullName).Access | Where-Object { $_.IdentityReference -like "*SYSTEM*" -or $_.IdentityReference -like "*Administrators*" }
}

```

**Finding Large Files**

```powershell
Get-ChildItem -Path [Path] -File -Recurse | Where-Object { $_.Length -gt [SizeInBytes] } | Select-Object FullName, Length

```

**Finding Executable Files**

```bash
Get-ChildItem -Path C:\Users -Include *.exe,*.bat,*.ps1 -File -Recurse -ErrorAction SilentlyContinue

```

**Finding Directories Writable by All Users**

```powershell
Get-ChildItem -Path [Path] -Directory -Recurse | Where-Object {
    (Get-Acl $_.FullName).Access | Where-Object { $_.FileSystemRights -like "*Write*" -and $_.IdentityReference -like "*Users*" }
}

```

**Using `Runas` to Execute CMD as a Different User**

```powershell
# Replace [Domain\Username] with the target username (e.g., backupadmin). You will be prompted to enter the password for the specified user.
runas /user:[Domain\Username] cmd

```
