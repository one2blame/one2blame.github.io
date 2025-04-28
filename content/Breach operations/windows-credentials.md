---
title: Windows credentials
tags:
  - breach
  - operations
  - windows
  - credentials
  - sam
  - ntlm
  - privilege
  - privileges
  - escalating
  - escalation
  - active
  - directory
---

## SAM database

The **Security Account Manager (SAM)** database stores local credentials for
Windows users as password hashes using the **NTLM** hashing format. NTLM hashes
can be used to authenticate to different machines, as long as the hash is tied
to a user account and password registered on the new machine.

It's unlikely you'll find matching local credentials applicable to users on
different machines - but there is the default **Administrator** account that can
be used for lateral movement. The Administrator account has been disabled by
default since the release of Windows Vista. Nevertheless, we'll discuss this
technique in the event a system administrator is using the Administrator
account.

We can invoke the following **PowerShell** to obtain the domain name of the
local computer and details about the Administrator account:

```powershell
$domain = $env:ComputerName
[wmi] "Win32_userAccount.Domain='$domain',Name='Administrator'"
```

The SAM database is stored at `C:\Windows\System32\config\SAM`, however, the
**SYSTEM**process has an exclusive lock on the file - we can't acquire a
**HANDLE** for it. To bypass this restriction, we can create a **shadow copy**
of the `C:\` drive using `wmic` in an administrative command prompt:

```cmd
wmic shadowcopy call create volume='c:\'
```

Verify that the shadow copy was created by invoking:

```cmd
vssadmin list shadows
```

And copy the SAM database and its encryption key, contained in the `SYSTEM`
file, by invoking:

```cmd
cp "${SAM_SHADOW_COPY_PATH}\Windows\System32\config\SAM" ${DESTINATION}
cp "${SAM_SHADOW_COPY_PATH}\Windows\System32\config\SYSTEM" ${DESTINATION}
```

Alternatively, we can acquire the SAM database and the SYSTEM file from the
registry:

```cmd
reg save HKLM\SAM ${DESTINATION}
reg save HKLM\SYSTEM ${DESTINATION}
```

Tools like [mimikatz](https://github.com/ParrotSec/mimikatz) and
[creddump7](https://github.com/CiscoCXSecurity/creddump7) can be used to decrypt
the SAM database using the acquired SYSTEM file. We can also use a
**meterpreter** agent with administrative privileges to execute the `hashdump`
command, dumping the NTLM hashes of a target machine.
