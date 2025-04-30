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

## LAPS

Managing credentials for privileged users is hard, so Microsoft created the
**Local Administrator Password Solution (LAPS)** to manage the local
administrator password for domain-joined computers. Using the
[LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit) **PowerShell** script,
we're able to enumerate which users or groups have the authorization to read
local administrator passwords for domain-joined computers.

## Access tokens

### Defining features

The Windows kernel issues users **access tokens** upon successful
authentication. These access tokens authorize users to create processes at a
certain **integrity level** with certain **privileges**.

#### What are integrity levels?

Windows defines four integrity levels:

- Low
- Medium
- High
- System Sandbox processes like web browsers run in a low integrity level.
  Applications spawned by a user run with a medium integrity level. High
  integrity level applications are spawned by administrators. The system
  integrity level is reserved for **SYSTEM** services.

A process of a lower integrity level cannot modify a process with a higher
integrity level. Local administrators are issued two (2) tokens upon
authentication, medium and high. When administrative users select "**Run as
administrator**", their high integrity level access token is used to invoke the
process. This action usually prompts for **User Account Control (UAC)** consent
from the administrator.

#### What are privileges?

**Privileges** are a set of access rights present within the token, defined by
two (2) bitmasks. They govern what actions a process can perform. The first
bitmask is immutable and describes the list of approved actions with the token.
The second bitmask is mutable, and describes which privileges are enabled or
disabled for the token. The state of the second bitmask can be updated with the
Win32 API method
[AdjustTokenPrivileges](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges).

We can inspect the current user's privileges by invoking the following:

```powershell
whoami /priv
```

We can also use the
[LsaAddAccountRights](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights)
API to add a set of privileges for a user, which will be assigned to that user's
access token next time they login. This can also be done by invoking the
`secpol.msc` application.

### Impersonation tokens

We can create **impersonation tokens**, allowing us to act on a user's behalf
without that user's credentials. These tokens have four levels, as well:

- Anonymous
- Identification
- Impersonation
- Delegation

The **anonymous** and **identification** impersonation tokens only allow for
enumeration of a user's information. **Impersonation** allows us to impersonate
the client's identity and **delegation** makes it possible to perform sequential
access control checks across multiple machines in the domain.
