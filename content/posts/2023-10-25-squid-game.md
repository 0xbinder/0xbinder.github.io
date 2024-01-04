---
author: pl4int3xt
layout: post
title: Squid Game
date: '2023-10-25 02:45:17 +0300'
cover: /img/cover_images/35.png
description: "Will you survive the Squid Games?"
categories: [BTLO, CTF-Like]
tags: [BTLO, Stegsolve, Steghide]
---

## Squid Game
Will you survive the Squid Games? 

## What is the phone number on the invitation card in Squid Game? (Research this online!) (5 points)
Do some google search and you'll get the phone number
```
8650 4006
```
## Can you extract something from the invitation card file? What is the name of the file? (5 points) 
Use the phone number to extract a file from the image
```
> steghide extract -sf Invitation\ Card.jpg
Enter passphrase: 
wrote extracted data to "Dalgona.png".
```
## What hint text can be discovered in the final file? (5 points) 
After using stegsolve we get this 
![img-description](/assets/img/squid-game/1.png)
## What is the final flag? (5 points) 