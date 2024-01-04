---
layout: post
title: Linux Forensics
date: '2023-10-13 16:11:36 +0300'
image: /assets/img/cover_images/31.png
categories: [Forensics, Linux]
tags: [Linux]
---

## Linux Forensics
Linux is the best-known and most-used open source operating system. As an operating system, Linux is software that sits underneath all of the other software on a computer, receiving requests from those programs and relaying these requests to the computer’s hardware.In fact, one of the most popular platforms on the planet, Android, is powered by the Linux operating system

## System and OS information
### OS release information:
```
/etc/os-release
```
### User accounts information
```
/etc/passwd
```
### User group information
```
/etc/group
```
### Sudoers list
```
/etc/sudoers
```
### Login information:
```
/var/log/wtmp
```
### Authentication logs:
```
/var/log/auth.log
```
## System configurations
### Hostname
```
/etc/hostname
```
### Timezone information
```
/etc/timezone
```
### Network Interfaces
```
/etc/network/interfaces
ip address show
```
### Open network connections
```
netstat –natp
```
### Running processes
```
ps aux
```
### DNS information
```
/etc/hosts
/etc/resolv.conf 
```
## Evidence Of Execution
### Authentication logs
```
/var/log/auth.log* |grep -i COMMAND
```
### Bash history
```
/home/<user>/.bash_history
```
### Vim history
```
/home/<user>/.viminfo
```
## Log Files
### Syslogs
```
/var/log/syslog
```
### Authentication logs:
```
/var/log/auth.log
```
### Third-party logs:
```
/var/log
```