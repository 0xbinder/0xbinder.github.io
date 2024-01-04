---
layout: post
title: Phishing Analysis 2
date: '2023-10-07 17:37:40 +0300'
image: /assets/img/cover_images/6.png
categories: [BTLO, Security Operations]
tags: [BTLO, Text Editor, Thunderbird, URL2PNG]
---

## Phishing Analysis 2
Put your phishing analysis skils to the test by triaging and collecting information about a recent phishing campaign. 

##  What is the sending email address? (1 points) 
we search From key word
```bash
From: Amazn <amazon@zyevantoby.cn>
```
##  What is the recipient email address? (1 points) 
we search To key word
```bash
To: saintington73 <saintington73@outlook.com>
```
##  What is the subject line of the email? (1 points) 
we search subject key word
```bash
Subject: Your Account has been locked
```
##  What company is the attacker trying to imitate? (1 points) 
We can see the attacker imitating amazon company
```bash
From: Amazn <amazon@zyevantoby.cn>
```
##  What is the date and time the email was sent? (As copied from a text editor) (1 points) 
we search Date key word
```bash
Date: Wed, 14 Jul 2021 01:40:32 +0900
```
##  What is the URL of the main call-to-action button? (1 points) 

We open the email with thunderbird and click on review account. we get this this
```bash
https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Famaozn.zzyuchengzhika.cn%2F%3Fmailtoken%3Dsaintington73%40outlook.com&data=04%7C01%7C%7C70072381ba6e49d1d12d08d94632811e%7C84df9e7fe9f640afb435aaaaaaaaaaaa%7C1%7C0%7C637618004988892053%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C1000&sdata=oPvTW08ASiViZTLfMECsvwDvguT6ODYKPQZNK3203m0%3D&reserved=0
```

##  Look at the URL using URL2PNG. What is the first sentence (heading) displayed on this site? (regardless of whether you think the site is malicious or not) (1 points) 

We open the url with URL2PNG and we get the first sentence

![img-description](/assets/img/phishing2/1.png)

##  When looking at the main body content in a text editor, what encoding scheme is being used? (1 points) 

base64 
```bash
Content-Transfer-Encoding: base64
```
##  What is the URL used to retrieve the company's logo in the email? (1 points) 

```bash
https://images.squarespace-cdn.com/content/52e2b6d3e4b06446e8bf13ed/1500584238342-OX2L298XVSKF8AO6I3SV/amazon-logo?format=750w&amp;content-type=image%2Fpng
```

##  For some unknown reason one of the URLs contains a Facebook profile URL. What is the username (not necessarily the display name) of this account, based on the URL? (1 points) 

The amazon Support team link contains the facebook profile url
```bash
https://emea01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fwww.facebook.com%2Famir.boyka.7&data=04%7C01%7C%7C70072381ba6e49d1d12d08d94632811e%7C84df9e7fe9f640afb435aaaaaaaaaaaa%7C1%7C0%7C637618004988892053%7CUnknown%7CTWFpbGZsb3d8eyJWIjoiMC4wLjAwMDAiLCJQIjoiV2luMzIiLCJBTiI6Ik1haWwiLCJXVCI6Mn0%3D%7C1000&sdata=KVi%2BG1%2BFO3v3ALNVowA1PrenHiT3aT%2FIvb5y1KxkAkc%3D&reserved=0
```