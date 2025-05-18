---
title: SEH overflows
tags:
  - stack
  - buffer
  - overflow
  - structured
  - exception
  - handler
  - seh
  - shellcode
  - gadgets
  - rop
  - x86
---

Windows uses **Structured Exception Handlers (SEH)** that can be registered for
the process when exceptions are encountered and help the process recover from
exceptions when they happen, when possible. Per thread, the **Thread Environment
Block (TEB)** structure keeps track of a linked list of registered exceptions
handlers. In **WinDbg**, we can inspect them as such:

```cmd
dt nt!_TEB
ntdll!_TEB
   +0x000 NtTib            : _NT_TIB

dt _NT_TIB
ntdll!_NT_TIB
   +0x000 ExceptionList    : Ptr32 _EXCEPTION_REGISTRATION_RECORD

dt _EXCEPTION_REGISTRATION_RECORD
typedef EXCEPTION_DISPOSITION _except_handler (*PEXCEPTION_ROUTINE) (
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN VOID EstablisherFrame,
    IN OUT PCONTEXT ContextRecord,
    IN OUT PDISPATCHER_CONTEXT DispatcherContext
);
```

We can also invoke the following in WinDbg to understand the exception handler
chain currently registered:

```cmd
!exchain
```

## SEH corruption

For the **x86** architecture, SEHs are hosted at the bottom of the stack and,
given a large enough buffer overflow, it's possible for us to corrupt the
contents of SEHs on the stack. When an exception handler is called, the
**EstablisherFrame** parameter is passed as the second argument to our
registered exception routine. If our exception routine can be corrupted to some
**ROP** gadget like `POP R32; POP R32; RET`, then we'll pop the return address
from the stack, pop the first argument from the stack, and then return into the
instructions pointed to by the **EstablisherFrame** argument - which just so
happens to be our shellcode most of the time.

Commonly in SEH overflow code execution, we'll need to do some island hopping to
avoid treating the address pointing to our `POP R32; POP R32; RET` as
instructions to be executed. The following payload example in **Python**
delivers an overflow that overwrites the exception handler routine of a SEH
frame to a `POP R32; POP R32; RET` ROP gadget. We then begin to execute the
beginning of the buffer which requires us to execute some **NOP** instructions
and a relative jump of 4 bytes, jumping over our ROP gadget. Finally, we add a
constant value to `sp` to move the stack pointer to our shellcode and execute
`jmp esp` to begin shellcode execution:

```python
payload = flat(
	[
		cyclic(cyclic_find("gaab")),
		0x06EB9090,
		Gadgets.pop_eax_pop_ebx_ret,
		b"\x90" * 2,
		b"\x66\x81\xc4\x30\x08",  # add sp, 0x830
		b"\xff\xe4",  # jmp esp
	]
)
```

### Stack canaries

Overflowing the SEH is a useful technique if the target maintains stack
canaries. When a stack canary value is invalid, exception handlers will be
invoked and, if we can corrupt enough of the stack to target the SEH tables, we
can still gain code execution despite corrupting the canary.

## SafeSEH

[SafeSEH](https://learn.microsoft.com/en-us/cpp/build/reference/safeseh-image-has-safe-exception-handlers?view=msvc-170)
is a mitigation to prevent code execution through the corruption of the SEH by
checking the exception handlers registered at runtime before they are executed.
With the `/SAFESEH` compiler parameter, the linker produces a program image that
maintains a table of the image's safe exception handlers.

## Related pages

- [[stack-buffer-overflow|Stack buffer overflow]]
- [[stack-canaries|Stack canaries]]
