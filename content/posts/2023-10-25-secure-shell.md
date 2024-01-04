---
author: pl4int3xt
layout: post
title: Secure Shell
date: '2023-10-25 14:35:27 +0300'
cover: /img/cover_images/38.png
description: "Hey! We had a SSH service on a system and noticed unusual change in size of the log file."
categories: [BTLO, Digital Forensics]
tags: [BTLO, Text Editor]
---
## Secure Shell
Hey! We had a SSH service on a system and noticed unusual change in size of the log file. 

## Is it an internal or external attack, what is the attacker IP? (5 points) 
From the log file we can see it is an external attack from the following ip
```
8380 2021-04-29 23:52:50.648 Connection from 192.168.1.17 port 49340 on 192.168.1.20 port 22
```
## How many valid accounts did the attacker find, and what are the usernames? (5 points) 