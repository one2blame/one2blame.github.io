---
title: Server-side request forgery
tags:
  - web-app
  - pentesting
  - server
  - side
  - request
  - forgery
---

**Server-side request forgery (SSRF)** is a scenario in which the attacker can coerce the vulnerable
server to make requests to other hosts on the attacker's behalf. For instance, the server implements
an API that translates to the server forwarding the request to a different microservice. The
attacker is able to provide arbitrary input for the forwarded request, allowing the attacker access
to data they otherwise wouldn't be able to acquire. The server is behaving as a proxy between the
attacker and services the server has authorization to access.

## Interacting with backend services

Without prior knowledge of the network topography for a distributed system, attackers will have a
tough time using SSRF to proxy requests through a vulnerable web server. There are some known
targets of interest for cloud-oriented architectures, however. For instance, Amazon Web Services
(AWS) provides virtual machines with the ability to query against a metadata service at
169.254.169.254, and the same goes for virtual machines in other cloud providers like Azure. More on
this below:

- [Use instance metadata to manage your EC2 instance](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html#instancedata-data-categories)
