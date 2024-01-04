---
layout: post
title: Employee of the year
date: '2023-10-05 19:52:40 +0300'
cover: img/cover_images/16.png
description: "John received the 'Best Employee of the Year' award for his hard work at FakeCompany Ltd. Unfortunately, today John deleted some important files (typical John!). It’s your job to recover the deleted files and capture all the flags contained within!"
categories: [BTLO, CTF-Like]
tags: [Foremost, Ransonmware]
---

## Employee of the Year
John received the 'Best Employee of the Year' award for his hard work at FakeCompany Ltd. Unfortunately, today John deleted some important files (typical John!). It’s your job to recover the deleted files and capture all the flags contained within! 

## What is the text written on the recovered gif image?
we are provided with recoverfile.dd. DD file is a disk image file and replica of a hard disk drive. 
First we run strings on the file
```bash
strings recoverfiles.dd | less
```
We get some hints on some flags from the output.
```bash
/media/splunk/20027131-e907-4aa4-a6c1-bdaa183a9b61
lost+found
Vanilla.gif
SBTCertifications.mp4
Flag3.pdf
Flag2.docx
Flag1.png
```
We will use foremost to recover deleted files from the recoverfile.dd file
```bash
foremost recoverfiles.dd 
```
we get one gif file image

![img-description](/assets/img/employee/1.png)

## Submit Flag1
Inside the png folder we find Flag1 png file.

![img-description](/assets/img/employee/2.png)

## Submit Flag2
The second flag is a docx file so We move to the zip file and unzip the file
```bash
unzip 00011120.zip
Archive:  00011120.zip
  inflating: word/numbering.xml      
  inflating: word/settings.xml       
  inflating: word/fontTable.xml      
  inflating: word/styles.xml         
  inflating: word/document.xml       
  inflating: word/_rels/document.xml.rels  
  inflating: _rels/.rels             
  inflating: word/theme/theme1.xml   
  inflating: [Content_Types].xml 
```
Word documents are a series of xml files and the document.xml is the main document file so we try to open it in an editor and we find a base64 encoded string

![img-description](/assets/img/employee/3.png)

We then decode it on the terminal. There is our flag
```bash
❯ echo RkxBRzI6QVNPTElEREVGRU5ERVI= | base64 -d
FLAG2:ASOLIDDEFENDER
```

## Submit Flag3
The third flag is from a pdf file and so we move to the pdf folder. After opening the pdf file we get this message

![img-description](/assets/img/employee/4.png)

I ran strings on the pdf file and i come across this

![img-description](/assets/img/employee/5.png)

From the ascii convertion table we get the character code 
```
%3A is decoded as “:”
%40 is decoded as “@”
%24 is decoded as “$”
```
We finally get our flag FLAG3:@BLU3T3AM$0LDI3R


## What is the filesystem of the provided disk image?
We use cfdisk to mount the image virtualy on our filesystem. 
```bash
cfdisk recoverfiles.dd
```
We then read the filesystem of the image.

![img-description](/assets/img/employee/6.png)

## What is the original filename of the recovered mp4 file?
We used strings before and saw an mp4 file. There is the file name
```bash
/media/splunk/20027131-e907-4aa4-a6c1-bdaa183a9b61
lost+found
Vanilla.gif
SBTCertifications.mp4
Flag3.pdf
Flag2.docx
Flag1.png
```