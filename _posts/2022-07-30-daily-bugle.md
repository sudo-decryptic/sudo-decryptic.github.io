---
title: THM - Daily Bugle
date: 2022-08-05 13:00:00 +0200
categories: [Writeups]
tags: [tryhackme, tutorial]     # TAG names should always be lowercase
---

Naturally, as a blue teamer I have the urge to identify which TTPs have been used during an attack. So from now on, all my write ups will include this by utilizing the MITRE ATT&CK framework. It can also serve as a hint for you before reading the in depth write up. The table below shows the TTPs used for the Daily Bugle room. 


| Reconnaissance | Initial Access | Persistence | Credential Access | Privilege Escalation |
|----------------|----------------|-------------|-------------------|----------------------|
| [T1595](https://attack.mitre.org/techniques/T1595/)          | [T1190](https://attack.mitre.org/techniques/T1190/)          | [T1505.003](https://attack.mitre.org/techniques/T1505/003/)   | [T1552.001](https://attack.mitre.org/techniques/T1552/001/)         | [T1548.003](https://attack.mitre.org/techniques/T1548/003/)            |
|                |                |             | [T1110.002](https://attack.mitre.org/techniques/T1110/002/)         |                      |


## Reconnaissance
Starting a TCP SYN scan we can see that the followign ports are open on the target host:

```
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
```
Opening a browser to visit the website running on the target host we see a blog by Daily Bugle. 
A newspaper in the Spiderman universe, run by Jonah Jameson. Looking at the HTTP headers we can see the PHP and Apache version running:
```
X-Powered-By: PHP/5.6.40
Server: Apache/2.4.6 (CentOS) PHP/5.6.40
```
Scouting the website does not reveal any version of a CMS being used. Checking robots.txt reveals an interesting page `/administrator`.
It contains a login wall to access what seems to be Joomla admin interface! We now know the CMS. However, still no Joomla version listed anywhere.
I decided to use gobuster with wordlist `urls-joomla-3.0.3.txt` provided by [SecLists](https://github.com/danielmiessler/SecLists).
However, it returns over 2791 pages with status 200 which is probably a good thing, but there must be a more efficient way to figure out which Joomla pages are interesting.
So back to Goolgle and I quickly found the following endpoint: `/administrator/manifests/files/joomla.xml`

Low and behold:
```xml
<version>3.7.0</version>
<creationDate>April 2017</creationDate>
```
## Initial Access
Now that we know the Joomla version we can check for known vulnerabilities and exploits. On [cvedetails.com](https://www.cvedetails.com/vulnerability-list/vendor_id-3496/product_id-33052/version_id-566072/Joomla-Joomla--3.7.0.html) we can see that the most serious one is CVE-2017-8917 regarding SQL Injection. Searching Metasploit there seems to be an exploit available: `exploit/unix/webapp/joomla_comfields_sqli_rce` Running the exploit returned an error I did not understand:

```console
metasploit: Exploit aborted due to failure: unknown: <TARGET_IP>:80 - Error retrieving table prefix
```
THM assignment we should try a Python script instead of SQLmap. However, being stubborn I wanted to try SQLMap on the login fields, but got the following error:
```shell
[10:23:22] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 4 times
```
Back to search for an exploit I found a Python script on Github by [SiopySec](https://github.com/SiopySec/CVE-2017-8917) which returned the following results:
```shell
* Database prefix : fb9j5
* Joomla user : jonah
* Joomla user mail : jonah@tryhackme.com
* Joomla user password : $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm
* Database user : root@localhost
* Database name : joomla
* Database version : 5.5.64-MariaDB
```
There we see a database prefix. perhaps this is was Metasploit needed? There was no option however to manually include the database prefix to the exploit options.
The password value is clearly hashed so we need a way to crack it. I used the following John the Ripper command for that:

```shell
┌──(kali㉿kali)-[~/TryHackMe/offensive-pentesting/dailybugle]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt --format=bcrypt hash.txt
```

## Persistence
With the password `spiderman123` cracked we head back to the administrator console and log in succesfully.
Now we need to a way to upload a webshell. I tried creating a blog and insert the php web shell in there but it seems to be commented automatically by Joomla.

So we need a different way. After a bit of Googling it seems php code can be inserted by adjusted templates in Extensions > Templates.
You will notice there are two themes. Protostar is the default, but we are going to use Beez3 to be more sneaky.
Here you can create a new file, insert the php web shell and save it as a .php file with whatever sneaky name you can think of.

The webshell can be activated with the following link: `http://<TARGET_IP>/templates/beez3/notawebshell.php`

Doing some initial enumeration on the machine I notice that my shell is non interactive. We can upgrade it to an interactive TTY with the following command:
```shell
$ python -c 'import pty;pty.spawn("/bin/bash")'; 
```

## Privilege Escalation
We are logged in as apache. In the previous THM rooms, similar service accounts were allowed to access the user home folder to grab the user flag.
However, only the user jjameson is has rwx permissions on his homefolder. So, we either need to move laterally to log in as jjameson to grab this flag or we skip this and go immediately for root.

I did the following enumration to go for root immediately:
* Checked capabilities manually, but no interesting binaries
* Checked sudo capabilities, but unable because it requires the password for apache user
* Checked suid/guid, but no interesting binaries
* Checked crontab, but nothing was scheduled
* Decided to use Linpeas and it found some kernel exploit and pkexec vulnerability.
* Checked for stored credentials with `grep -r "password" /var`

The last check resulted in a plaintext password located in a Joomla configuration file `/var/www/html/configuration.php`:
```php
<?php
class JConfig {
        public $user = 'root';
        public $password = 'nv5uz9r3ZEDzVjNu';
        public $db = 'joomla';
        public $dbprefix = 'fb9j5_';
}
```

Great so now we have root access to the mysql database, but is it maybe also the password for the root user? Unfortunetaly not.
Admittedly it took a while for me to realize that maybe I should test this password for use jjameson...

After successfully grabbing the use flag we continue with enumeration to escalate our privileges.
We were enable to check `sudo -l` because of a lack of a password, but now we can and it seems we can run the yum package manager with root privileges.

Checking [gtfobins](https://gtfobins.github.io/gtfobins/yum/#sudo) we find two options to escalate our privileges. The first one is to run any command as root and the other onee creates a custom plugin to start an interactive shell!

`sudo yum -c $TF/x --enableplugin=y` 

The end.