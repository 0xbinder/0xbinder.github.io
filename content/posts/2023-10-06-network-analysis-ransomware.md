---
layout: post
title: Network Analysis - Ransomware
date: '2023-10-06 10:16:18 +0300'
categories: [BTLO, Security Operations]
image: /assets/img/cover_images/15.png
tags: [BTLO, Wireshark, Tshark, Ransonmware, Teslacrypt, VirusTotal]
---

## Network Analysis - Ransomware
ABC Industries worked day and night for a month to prepare a tender document for a prestigious project that would secure the company’s financial future. The company was hit by ransomware, believed to be conducted by a competitor, and the final version of the tender document was encrypted. Right now they are in need of an expert who can decrypt this critical document. All we have is the network traffic, the ransom note, and the encrypted ender document. Do your thing Defender!​ 

## What is the operating system of the host from which the network traffic was captured? (Look at Capture File Properties, copy the details exactly) 

We open the ransom_traffic.pcapng with wireshark and navigate to Statistics->Capture File Properties

![img-description](/assets/img/network-analysis-ransomware/1.png)

## What is the full URL from which the ransomware executable was downloaded?
We can see a GET request from the screenshot

![img-description](/assets/img/network-analysis-ransomware/2.png)

We Move to File-> Export Objects->Http

![img-description](/assets/img/network-analysis-ransomware/3.png)

## Name the ransomware executable file?

We can see the name from the above screenshot

## What is the MD5 hash of the ransomware?

Let's upload the file to virus total

![img-description](/assets/img/network-analysis-ransomware/4.png)

## What is the name of the ransomware?

We can see that the name of the ransomware is teslacrypt

![img-description](/assets/img/network-analysis-ransomware/5.png)

## What is the encryption algorithm used by the ransomware, according to the ransom note?

From the help_recover_instructions.TXT file we can see the algorithm use for encryption
```bash
What happened to your files ?
All of your files were protected by a strong encryption with RSA-4096.
More information about the encryption keys using RSA-4096 can be found here: http://en.wikipedia.org/wiki/RSA_(cryptosystem)
```

## What is the domain beginning with ‘d’ that is related to ransomware traffic?

Let's check the contacted domains from virus total

![img-description](/assets/img/network-analysis-ransomware/6.png)

## Decrypt the Tender document and submit the flag

Download the [tesladecrypt](https://github.com/Cisco-Talos/TeslaDecrypt.git) and decrypt the file Tender.pdf.micro

The flag is BTLO-T3nd3r-Fl@g