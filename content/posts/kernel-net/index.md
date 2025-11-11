<!-- ---
author: 0xbinder
layout: post
title: Kernel Net
date: '2025-11-11'
description: "A in-kernel prototype inference engine for hosting mysterious models."
useRelativeCover: true
categories: [Mobile Hacking Lab]
---

![img-description](featured.png)


## Distribution files
The source code for the custom kernel driver, kernel commit hash, debug kernel and corellium kernel along with vmlinux has been provided in the attachment.

[Kern-net.zip](https://weurope1.blob.core.windows.net/kernel/kern-net.zip)

Debug environment credentials:
- Unprivileged user : mhl:hacker
- Privileged user      : root:toor
## Objective

Your goal is to escalate your privileges and obtain the flag located at /data/vendor/secret/flag.txt.

## Sidenote
The debug environment was built to closely mirror the Corellium device, excluding SELinux. Validate your exploit against the debug environment first; port it to the Corellium device only after successful validation on debug environment.
 -->
