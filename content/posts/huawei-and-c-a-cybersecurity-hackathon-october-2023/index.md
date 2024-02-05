---
author: pl4int3xt
layout: post
title: Huawei and C.A Cybersecurity Hackathon October 2023
date: '2023-11-02'
cover: /img/cover_images/39.png
description: "Huawei and C.A Cybersecurity Hackathon October 2023"
categories: [Capture The Flag]
---

## Mobile app security
### What is the sha256 hash of the app?
Use sha256sum to get the sha256 hash of the app
```bash
sha256sum KE-CIRT_1.5.0_apkcombo.com.apk
0e3a2e7d2a1bb49bc5b1d1bc824ea410fe7bcc40abde7d25ecb7e58253a62503
```
### How many permissions are there on the app and how many are marked as dangerous?
We use [mobsf live](https://mobsf.live/) to scan the app and get the details of the permissions. The dangerpus ones are 13 while all the permissions are 47

![img-description](7.png)

### What is the value of the serial number of the certificate in the application?
We can use jadx-gui to decompile the apk and check the serial number version under the apk signature

![img-description](5.png)

### What is the vulnerability of the certificate used in the application?
From mobsf scan we are able to see the vulnerability. Janus Vulnerability

![img-description](6.png)
### What is the value of glEsVersion in the android manifest file?
We need to first decompile the apk file using apktool
```bash
apktool d KE-CIRT_1.5.0_apkcombo.com.apk
```
we then move to the directory of the decompiled file and grep the android manifest file
```bash
cat AndroidManifest.xml | grep -i glEsVersion
<uses-feature android:glEsVersion="0x00020000" android:required="true"/>
```
## Web security
### What is the php version of the web app running on the ip?
There are several ways to solve this you can use whatweb which is a command line tool or wapplyzer which is an extension. This will display the version of the php.
```bash
whatweb 192.168.1.102
```
### What is the version of the apache server running?
FRom the last command you'll get the version of the apache server running.
### What is the ftp server running on the webserver?
We use nmap to scan the ip and from the output we get filezilla as the ftp server running on the web server
```bash
nmap -sV -sC -T5 -Pn 10.10.11.233
```
### What is the user login on the ftp server?
The default user login in ftp server without any credentials is the 
```
anonymous
```
## Network forensics
### What is the password of the wifi?
since the file is a png file we use zsteg to get the hidden content in the file
```bash
zsteg Huawei.png
b1,r,lsb,xy         .. text: "FBFFBBFFFFFFFFBFBBFBBBBBBBBBBFBBB"
b1,r,msb,xy         .. text: "bBbbBBbbbbbbbbBbBBbBBBBBBBBBBbBBB"
b1,rgb,lsb,xy       .. text: "01000001 01100100 01101101 01101001 01101110 01000000 01000000 00110010 00110000 00110011 00110000 "
```
we find it is a binary encrypted file. Take the binary code and slap it in cyberchef and wait it to do its magic
![img-description](3.png)

### What is the sha1 hash of the pcap file?
We use sha1sum
```bash
sha1sum KEHACKATHON-Finals.pcapng
b421a185aa64e3aeb924c9c3d02f4b09e336182f
```
### Number of packets captured in the file?
We navigate to Statistics > Capture file properties

![img-description](4.png)

### Total time taken to capture the file?
We navigate to Statistics > Capture file properties. The elapsed time

![img-description](2.png)

### At what time was the pcap image captured?
We navigate to Statistics > Capture file properties. First packet time 

![img-description](2.png)
### What was the software used to connect remotely to the server?
We follow the tcp stream and come to this file. The software is PuTTY

![img-description](1.png)
### What was the service used to connect to the server?
On the same file we can see the service was SSH

![img-description](1.png)
