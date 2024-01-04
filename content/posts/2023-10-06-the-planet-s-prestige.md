---
layout: post
title: The Planet's prestige
date: '2023-10-06 21:06:45 +0300'
image: /assets/img/cover_images/11.png
categories: [BTLO, CTF-Like]
tags: [Email Client, Text Editor, Pdf-Parser, Base64, Xlsx]
---

## The Planet's Prestige
CoCanDa, a planet known as 'The Heaven of the Universe' has been having a bad year. A series of riots have taken place across the planet due to the frequent abduction of citizens, known as CoCanDians, by a mysterious force. CoCanDa’s Planetary President arranged a war-room with the best brains and military leaders to work on a solution. After the meeting concluded the President was informed his daughter had disappeared. CoCanDa agents spread across multiple planets were working day and night to locate her. Two days later and there’s no update on the situation, no demand for ransom, not even a single clue regarding the whereabouts of the missing people. On the third day a CoCanDa representative, an Army Major on Earth, received an email. 

## What is the email service used by the malicious actor?

We open the file with a text editor and from Received we can see the email service used by attacker

```
Received: from localhost (emkei.cz. [93.99.104.210])
        by mx.google.com with ESMTPS id s16si170171wmj.176.2021.01.25.22.41.18
        for <themajoronearth@gmail.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Jan 2021 22:41:18 -0800 (PST)
```
## What is the Reply-To email address?

We can see the reply to email
```bash
Reply-To: negeja3921@pashter.com
```
## What is the filetype of the received attachment which helped to continue the investigation?

I use [Aspose](https://products.aspose.app/email/parser/eml) to parse the email and download the content. We get a pdf file and try to check it and found it is not a valid pdf.
```bash
pdfid PuzzleToCoCanDa.pdf
PDFiD 0.2.8 PuzzleToCoCanDa.pdf
 Not a PDF document
```
We run strings on the file and we get this hint that there are other files inside it so it might be a zip file.
```bash
spH)K
oS:R
PuzzleToCoCanDa/Money.xlsx
<_mu
E<!v
```
We then unzip the file and indeed it was a zip file.
```bash
7z x PuzzleToCoCanDa.pdf
```
## What is the name of the malicious actor?
I checked the first file and it was an image and it did not have the name. The second file was a pdf file
```bash
file GoodJobMajor
GoodJobMajor: PDF document, version 1.5, 1 pages
```
We add the extension to the pdf and run it with pdf-parser. We get the author
```bash
obj 21 0
 Type: 
 Referencing: 

  <<
    /Author (Pestero Negeja)
    /Producer (Skia/PDF m90)
  >>


xref
```
## What is the location of the attacker in this Universe
We extract the contents of the xlsx file since it is a bunch of xml files. I opened the files and came across this file sharedStrings.xml which had a base64 encoded string

![img-description](/assets/img/planet-prestige/1.png)

We try to decode it and we get the location
```bash
echo VGhlIE1hcnRpYW4gQ29sb255LCBCZXNpZGUgSW50ZXJwbGFuZXRhcnkgU3BhY2Vwb3J0Lg== | base64 -d
The Martian Colony, Beside Interplanetary Spaceport.
```
## What could be the probable C&C domain to control the attacker’s autonomous bots?

The domain listed in the reply to is likely to be the command and control domain since is the channel to reach the attacker.