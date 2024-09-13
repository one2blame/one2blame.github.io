---
title: Insecure direct object referencing
tags:
  - web-app
  - pentesting
  - insecure
  - direct
  - object
  - referencing
---

**Insecure direct object referencing (IDOR)** describes a class of vulnerability in a web
application that allows attackers to disclose information by brute forcing references to objects on
the web application's backend. For example, a web application referencing all users with a simple
user ID in the range `0 ... 100`, and allowing `GET` requests against arbitrary user IDs, enabling
attackers to exfiltrate user information for an arbitrary number of users. More on IDOR:

- [PortSwigger - Insecure direct object referencing](https://portswigger.net/web-security/access-control/idor)
- [OWASP - Insecure Direct Object Reference Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html#introduction)
