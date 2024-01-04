---
layout: post
title: Nmap Scanning Techniques
date: '2023-10-26 12:35:11 +0300'
cover: /img/cover_images/37.png
description: "Nmap scanning techniques"
categories: [Pentesting, Nmap]
tags: [Nmap]
---
## Nmap
## Hostname discovery
```bash
nmap --script smb-os-discovery 10.129.238.214
```
## Host discovery
```bash
sudo nmap 10.129.2.0/24 -sn
```
## Services and their versions
```bash
nmap -sV [ip]
```
## List of targets
```bash
nmap -iL targets.txt
```
## Service with Os detection
```bash
nmap -sV -O [ip]
```
## Fast mode
```bash
nmap -sV -F -O [ip]
```
## Aggressive scan
```bash
nmap -A [ip]
```
## Scripting engine
```bash
nmap -sC [ip]
nmap --script=default vuln [ip]
nmap --script vuln [ip]
```
## Service detection with script engine
```bash
nmap -sV -sC [ip]
```
## Tcp scan on all ports
```bash
nmap -sT -p- [ip]
```
## UDP aggressive scan
```bash
nmap -sU -T4 [ip]
```
## Port range
```bash
sudo nmap -p 1-3000 -sC -sV 10.129.82.32
```
## Most common ports in fast mode
```bash
nmap --top-ports 100 -F [ip]
```
## Firewall and IDS evasion
```bash
nmap -sS -T1 -F [ip]
nmap -sS -T1 [ip]
nmap -FN -T1 [ip]
nmap -D ip1,ip2,RND,RND,yourip [target_ip]
nmap -sV --scripts-args https.useragent="" [ip]
sudo nmap 10.129.2.28 -n -Pn -p 445 -O -S 10.129.2.200 -e tun0
sudo nmap 10.129.2.28 -p 80 -sS -Pn -n --disable-arp-ping --packet-trace -D RND:5
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53
ncat -nv --source-port 53 10.129.2.28 50000
```
## Spoofed scan
```bash
nmap -e eth0 -Pn -S spoofed_ip [target_ip]
```
## Scanning speed
```T1``` is the slowest but the best to avoid IDS alerts, also ```T2```. ```T3``` is the normal one for Nmap.```T4``` is used for ctf's or when learning to scan with nmap.```T5``` is fast but has low accuracy due to packet loss.
```bash
--min-rate [number]
--max-rate [number]
```
can also be used as an alternative to specify the number of packets to be send per second
## Detecting Firewalls
If we get filtered fron the Null, FIN, XMAS scan it means firewalls are present. In Null scan 0 flags are set to 1. FIN Scan 1 flag is set to 1 and Xmas scan 3 are set to 1.
```bash
nmap -sN [ip]
nmap -sF [ip]
nmap -sX [ip]
```