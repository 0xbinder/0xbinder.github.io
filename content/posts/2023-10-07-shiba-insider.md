---
layout: post
title: Shiba Insider
date: '2023-10-07 17:03:24 +0300'
image: /assets/img/cover_images/7.png
categories: [BTLO, Digital Forensics]
tags: [BTLO, Wireshark, ExifTool, Steghide]
---

## Shiba Insider
Can you uncover the insider? 


##  What is the response message obtained from the PCAP file? (1 points) 

We open the file with wireshark and follow the TCP stream and get the message in clear text

![img-description](/assets/img/shiba/1.png)

##  What is the password of the ZIP file? (1 points) 

The authorization token is base64 encoded so we try to decode it and get both username and password in string
```bash
echo ZmFrZWJsdWU6cmVkZm9yZXZlcg== | base64 -d
fakeblue:redforever
```

##  Will more passwords be required? (1 points) 

No. We opened the file with only one password no more passwords required

##  What is the name of a widely-used tool that can be used to obtain file information? (1 points) 

ExifTool

ExifTool is a platform-independent Perl library plus a command-line application for reading, writing and editing meta information in a wide variety of files. ExifTool supports many different metadata formats.

##  What is the name and value of the interesting information obtained from the image file metadata? (1 points) 

Technique.Steganography

```bash
exiftool ssdog1.jpeg
ExifTool Version Number         : 12.60
File Name                       : ssdog1.jpeg
Directory                       : .
File Size                       : 84 kB
File Modification Date/Time     : 2021:09:26 23:07:52+03:00
File Access Date/Time           : 2023:10:07 17:10:49+03:00
File Inode Change Date/Time     : 2023:10:07 17:11:00+03:00
File Permissions                : -rw-r--r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
XMP Toolkit                     : Image::ExifTool 11.88
Technique                       : Steganography
Technique Command               : steghide
Image Width                     : 1080
Image Height                    : 1018
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:4:4 (1 1)
Image Size                      : 1080x1018
Megapixels                      : 1.1
```

##  Based on the answer from the previous question, what tool needs to be used to retrieve the information hidden in the file? (1 points) 

Steghide is a steganography program that is able to hide data in various kinds of image- and audio-files.

##  Enter the ID retrieved. (1 points) 

We extract hidden data first
```bash
steghide extract -sf ssdog1.jpeg
Enter passphrase: 
wrote extracted data to "idInsider.txt".
```
We read the content of the output file
```bash
cat idInsider.txt
0726ba878ea47de571777a
```
##  What is the profile name of the attacker? (3 points) 

The challenge was about an insider so i thought this guy must be a user at BTLO so i tried to change the url as follows
```bash
https://blueteamlabs.online/home/user/0726ba878ea47de571777a
```
And boom we got the user 

![img-description](/assets/img/shiba/2.png)