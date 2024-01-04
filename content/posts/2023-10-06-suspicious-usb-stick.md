---
layout: post
title: Suspicious USB Stick
date: '2023-10-06 11:36:55 +0300'
image: /assets/img/cover_images/13.png
categories: [BTLO, CTF-Like]
tags: [VirusTotal, USB, Pdf-Parser, HexDump, Magic Bytes, Pdfid]
---

## Suspicious USB Stick
One of our clients informed us they recently suffered an employee data breach. As a startup company, they had a constrained budget allocated for security and employee training. I visited them and spoke with the relevant stakeholders. I also collected some suspicious emails and a USB drive an employee found on their premises. While I am analyzing the suspicious emails, can you check the contents on the USB drive? 

## What file is the autorun.inf running?
autorun.inf — It’s a text file that can be used to automatically run some applications or load when some media like usb,cd/dvd is inserted. Let's strings the autorun.inf. We can see the file which will be opened by autorun.inf
```bash
❯ strings autorun.inf
[autorun]
open=README.pdf
icon=autorun.ico
```

## Does the pdf file pass virustotal scan? (No malicious results returned) 

The pdf file does not pass the virus total scan since it is a valid virus

![img-description](/assets/img/suspicious-usb/1.png)

## Does the file have the correct magic number? 

We can see that the magic bytes are correct from [wikipedia](https://en.wikipedia.org/wiki/List_of_file_signatures)
```bash
❯ hexdump -C README.pdf -n20
00000000  25 50 44 46 2d 31 2e 37  0d 0a 25 b5 b5 b5 b5 0d  |%PDF-1.7..%.....|
00000010  0a 31 20 30                                       |.1 0|
00000014
```

## What OS type can the file exploit? (Linux, MacOS, Windows, etc) 

we run pdf-parser to read the contents of the pdf
```bash
pdf-parser README.pdf 
```
We come across this and we can now see the operating system 
```bash
obj 28 0
 Type: /Action
 Referencing: 

  <<
    /S /Launch
    /Type /Action
    /Win
      <<
        /F (cmd.exe)
        /D '(c:\\\\windows\\\\system32)'
        /P '(/Q /C %HOMEDRIVE%&cd %HOMEPATH%&(if exist "Desktop\\\\README.pdf" (cd "Desktop"))&(if exist "My Documents\\\\README.pdf" (cd "My Documents"))&(if exist "Documents\\\\README.pdf" (cd "Documents"))&(if exist "Escritorio\\\\README.pdf" (cd "Escritorio"))&(if exist "Mis Documentos\\\\README.pdf" (cd "Mis Documentos"))&(start README.pdf)\n\n\n\n\n\n\n\n\n\nTo view the encrypted content please tick the "Do not show this message again" box and press Open.)'
      >>
  >>
```

## A Windows executable is mentioned in the pdf file, what is it?

From above we can see Cmd.exe which is a windows executable.

## How many suspicious /OpenAction elements does the file have?

We use pdfid to get some information about the pdf and from there we can see /OpenAction
```bash
❯ pdfid README.pdf
PDFiD 0.2.8 README.pdf
 PDF Header: %PDF-1.7
 obj                   25
 endobj                25
 stream                 7
 endstream              7
 xref                   4
 trailer                4
 startxref              4
 /Page                  2
 /Encrypt               0
 /ObjStm                1
 /JS                    1
 /JavaScript            1
 /AA                    1
 /OpenAction            1
 /AcroForm              0
 /JBIG2Decode           0
 /RichMedia             0
 /Launch                1
 /EmbeddedFile          0
 /XFA                   0
 /Colors > 2^24         0
```