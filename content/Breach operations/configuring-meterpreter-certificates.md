---
title: Configuring Meterpreter certificates
tags:
  - breach
  - operations
  - meterpreter
  - certificates
  - bypass
  - ids
  - ips
---

Some **Intrusion Detection Systems (IDS)** or **Intrusion Prevention Systems
(IPS)** block HTTPS connections to particular sites if they recognize malicious
certificates being offered for **Secure Sockets Layer (SSL)** communication with
a downstream client. **Meterpreter** by default randomizes the certificate it
offers for HTTPS connections when delivering second stage payloads for first
stage payload callbacks.

It's probably a good a idea to register a domain and generate a valid
certificate using a service like [Let's Encrypt](https://letsencrypt.org/) to
bypass this security mechanism, and we'll discuss that later. For now, you can
invoke the following to generate a new certificate that can be used by
meterpreter:

```bash
openssl req -new -x509 -nodes -out cert.crt -keyout priv.key
```

Then you can easily generate a valid `.pem` file by concatenating the
certificate and private key:

```bash
cat priv.key cert.crt > mycert.pem
```

Finally, we can set meterpreter's handler certificate to our self-signed
certificate, possibly bypassing IDS and IPS and allowing us to establish SSL
communications with our payload's first stage callback:

```bash
msfconsole > set HandlerSSLCert ./mycert.pem
```

## Certificate pinning

Some networks will implement a man-in-the-middle (MITM) web proxy that
terminates a client's SSL request, unpacks the application layer request to
conduct deep packet inspection, and then repacks the request, forwarding it if
it's not malicious or dropping it otherwise. Our meterpreter first stage
payloads can run into problems with these kind of protection mechanism.

If our meterpreter stager establishes a reverse HTTPS connection to download the
next stage payload from our C2, if it doesn't verify the SSL certificate offered
by the server, a MITM web proxy could be impersonating our C2. With the
**StagerVerifySSLCert** option for stager creation, we can avoid this scenario -
invalid certificates will cause the stager to de-rez. More on stager certificate
pinning can be found here:
[TLS Certificate Pinning](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-http-communication.html#tls-certificate-pinning).
