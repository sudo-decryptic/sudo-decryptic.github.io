---
title: Cheat Sheet
date: 2022-08-05 16:00:00 +0200
categories: [Cheatsheets]
tags: [commands, shell]     # TAG names should always be lowercase
---

## Cracking hash

### John the Ripper
When using a custom format we can specify the hash algoritm(s) and the format with the `--format` parameter.

Example cipher (SHA512$salt):
```
6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed$1c362db832f3f864c8c2fe05f2002a05
```
Command:

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt --format='dynamic=sha512($p.$s)' hash.txt
```

## SMB

```shell
nmap -p 445 -Pn -n --script smb-enum-* <TARGET_IP>
smbclient -U 'guest' \\\\10.10.133.84\\<SHARENAME> #FTP like, use 'get' to download file
xdg-open smb://<TARGET_IP>/<SHARENAME> #connects share to local file explorer
```

## RDP

```shell
xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:<TARGET_IP> /u:<USER> /p:'<PASSWORD>' 
```

