---
title: Commands
tags:
  - commands
  - enumeration
  - pentesting
---
## Enumeration
Scan the 1000 most common ports, skip host discovery
```bash
nmap -Pn {IP_ADDRESS : HOSTNAME}
```
Scan the 1000 most common ports, [conduct service and version detection](https://nmap.org/book/man-version-detection.html)
```bash
nmap -sV {IP_ADDRESS : HOSTNAME}
```
Enumerate HTTP methods accepted by an HTTP server
```bash
nmap -p 80 --script http-methods {IP_ADDRESS : HOSTNAME}
```
Get headers from an HTTP server response
```bash
curl -I http://{IP_ADDRESS : HOSTNAME}
```
Banner grab an arbitrary open port
```bash
netcat -v {IP_ADDRESS : HOSTNAME} {PORT}
```
Crawl a web application for HTTP endpoints using [Hakrawler](https://github.com/hakluke/hakrawler)
```bash
echo "http://{IP_ADDRESS : HOSTNAME}" | hakrawler -u
```
Use a wordlist to discover HTTP endpoints with [DIRB](https://dirb.sourceforge.net/)
```bash
dirb http://{IP_ADDRESS : HOSTNAME}
```
Use a wordlist to discover HTTP endpoints with a specific extension with DIRB
```bash
dirb http://{IP_ADDRESS : HOSTNAME} -X .php
```
Fuzz usernames with a wordlist to attempt information disclosure of valid usernames with [ffuf](https://github.com/ffuf/ffuf)
```bash
ffuf -w wordlist.txt -u http://{IP_ADDRESS : HOSTNAME}/{ENDPOINT} -X POST -d 'username=FUZZ&password=bar' -H 'Content-Type: application/x-www-form-urlencoded'
```
Get a server's HTTP options and CORS policy:
```bash
curl -X "OPTIONS" -i -k https://<IP_ADDRESS>
```
## Wordlists
Creating a custom wordlist from a URL using [CeWL](https://github.com/digininja/CeWL)
```bash
cewl --write output.txt --lowercase -m 4 http://{IP_ADDRESS : HOSTNAME}
```

## Kali Linux
List available wordlists
```bash
ls -alh /usr/share/wordlists
```
List available webshells
```bash
tree /usr/share/webshells
```