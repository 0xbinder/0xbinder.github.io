---
layout: post
title: Volatility
date: '2023-10-09 19:19:00 +0300'
image: /assets/img/cover_images/29.png
categories: [Forensics, Volatility]
tags: [RAM, Volatility2, Volatility3]
---

## Volatility : The volatile memory extraction framework
[Volatility](https://github.com/volatilityfoundation/volatility3) is the world's most widely used framework for extracting digital artifacts from volatile memory (RAM) samples.

## OS Information
volatility2
```
vol.py -f 'test.vmem' imageinfo
```
volatility3
```
vol.py -f 'test.vmem' windows.info
```
## Process Information
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] pslist
vol.py -f 'test.vmem' --profile=[profile] psscan
vol.py -f 'test.vmem' --profile=[profile] pstree
vol.py -f 'test.vmem' --profile=[profile] psxview
```
volatility3
```
vol.py -f 'test.vmem' windows.pslist
vol.py -f 'test.vmem' windows.psscan
vol.py -f 'test.vmem' windows.pstree
```
## Process dump
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] procdump -p [PID] --dump-dir="/path/to/dir"
```
volatility3
```
vol.py -f 'test.vmem' windows.dumpfiles --pid [PID]
```
## Memory dump
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] memdump -p [PID] --dump-dir="/path/to/dir"
```
volatility3
```
vol.py -f 'test.vmem' windows.memdump.MemMap --pid [PID] --dump
```
## Handles 
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] handles -p [PID]
```
volatility3
```
vol.py -f 'test.vmem' windows.handles --pid [PID]
```
## DLLs
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] dlllist -p [PID]
```
volatility3
```
vol.py -f 'test.vmem' windows.dlllist --pid [PID]
```
## CommandLine
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] cmdline
vol.py -f 'test.vmem' --profile=[profile] cmdscan
vol.py -f 'test.vmem' --profile=[profile] consoles
```
volatility3
```
vol.py -f 'test.vmem' windows.cmdline
```
## Network Information
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] netscan
vol.py -f 'test.vmem' --profile=[profile] netstat
```
volatility3
```
vol.py -f 'test.vmem' windows.netscan
vol.py -f 'test.vmem' windows.netstat
```
## Registry
### Hivelist
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] hivescan
vol.py -f 'test.vmem' --profile=[profile] hivelist
```
volatility3
```
vol.py -f 'test.vmem' windows.registry.hivescan
vol.py -f 'test.vmem' windows.registry.hivelist
```
### PrintKey
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] printkey
vol.py -f 'test.vmem' --profile=[profile] printkey -K "Software\Microsoft\Windows\CurrentVersion"
```
volatility3
```
vol.py -f 'test.vmem' windows.registry.printkey
vol.py -f 'test.vmem' windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion"
```
### Hivedump
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] hivedump -o [offset]
```
volatility3
```
vol.py -f 'test.vmem' windows.dumpfiles --virtaddr [offset]
```
## Files
### Filescan
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] filescan
```
volatility3
```
vol.py -f 'test.vmem' windows.filescan
```
### File dump
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] dumpfiles --dump-dir="/path"
vol.py -f 'test.vmem' --profile=[profile] dumpfiles --dump-dir="/path" -Q [offset]
vol.py -f 'test.vmem' --profile=[profile] dumpfiles --dump-dir="/path" -p [offset]
```
volatility3
```
vol.py -f 'test.vmem' windows.dumpfiles
vol.py -f 'test.vmem' windows.dumpfiles --virtaddre [offset]
vol.py -f 'test.vmem' windows.dumpfiles --physaddr [offset]
```
## MISC
### Malfind
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] malfind
```
volatility3
```
vol.py -f 'test.vmem' windows.malfind
```
### Yarascan
volatility2
```
vol.py -f 'test.vmem' yarascan -y '/path_to_yar'
```
volatility3
```
vol.py -f 'test.vmem' windows.vadyarascan --yara-rules [string]
vol.py -f 'test.vmem' windows.vadyarascan --yara-file '/path_to_yar'
vol.py -f 'test.vmem' yarascan.yarascan --yara-file '/path_to_yar'
```
### Shutdowntime
volatility2
```
vol.py -f 'test.vmem' --profile=[profile] shutdowntime
```