---
author: 0xbinder
layout: post
title: The apktool
date: '2023-10-05 01:54:43 +0800'
description: "Learn about the apktool that allows you to assemble APK files and build them again after manipulating the smali code"
categories: [Android hacking 101]
tags: [Android, Reverse Engineering, Apktool]
---

## The apktool
The main features are the ability to disassemble the APK, allowing this way to read and make changes to the source code, and then rebuild the resources back to the APK file. This lets the user change the functionality of the application. Let’s assume that we have the following application, and we want to try to bypass the Root detection.

![img-description](1.png)

To bypass we need to reverse engineer find and edit the root checker function and then recompile the apk. We will use the apktool which will provide us with [Smali]() code which is harder to read and understand. To understand the code let's check the java code from jadx first.

![img-description](2.png)

From the code above we see an if check being run to see whether the device is rooted or not. We need to edit it inorder to bypass root detection.
```bash
apktool d AndroGoat.apk
I: Using Apktool 2.7.0 on AndroGoat.apk
I: Loading resource table...
I: Decoding AndroidManifest.xml with resources...
I: Loading resource table from file: /home/user/.local/share/apktool/framework/1.apk
I: Regular manifest package...
I: Decoding file-resources...
I: Decoding values */* XMLs...
I: Baksmaling classes.dex...
I: Copying assets and libs...
I: Copying unknown files...
I: Copying original files...
```
let's list the contents of the file
```bash
ls -lah
Permissions Size User  Date Modified Name
.rw-r--r--  4.3k user  4 Oct 21:26  AndroidManifest.xml
.rw-r--r--   561 user  4 Oct 21:26  apktool.yml
drwxr-xr-x     - user  4 Oct 21:26  kotlin
drwxr-xr-x     - user  4 Oct 21:26  original
drwxr-xr-x     - user  4 Oct 21:26  res
drwxr-xr-x     - user  4 Oct 21:26  smali
drwxr-xr-x     - user  4 Oct 21:26  unknown
```
we can see the smali file.Smali code is an assembler/disassembler for the dex format used by dalvik, Android's Java VM implementation. Since we have access to the smali code, we can read it, change it, and recompile it using Apktool. Let's list the activities in the smali file
```bash
ls -lah smali/owasp/sat/agoat/
Permissions  Size User   Date Modified Name
.rw-r--r--   1.9k user  4 Oct 21:26  AccessControl1ViewActivity$onCreate$1.smali
.rw-r--r--   4.6k user  4 Oct 21:26  AccessControl1ViewActivity.smali
.rw-r--r--   3.5k user  4 Oct 21:26  AccessControlIssue1Activity$hashPIN$md$1.smali
.rw-r--r--   4.4k user  4 Oct 21:26  AccessControlIssue1Activity$onCreate$1.smali
.rw-r--r--   4.9k user  4 Oct 21:26  AccessControlIssue1Activity$verifyPINView$1.smali
.rw-r--r--    11k user  4 Oct 21:26  AccessControlIssue1Activity.smali
.rw-r--r--   2.2k user  4 Oct 21:26  BinaryPatchingActivity$onCreate$1.smali
.rw-r--r--   5.5k user  4 Oct 21:26  BinaryPatchingActivity.smali
.rw-r--r--    874 user  4 Oct 21:26  BuildConfig.smali
.rw-r--r--   7.1k user  4 Oct 21:26  ClipboardActivity$onCreate$1.smali
.rw-r--r--   4.1k user  4 Oct 21:26  ClipboardActivity.smali
```
We get alot of activities but we are interested with the RootDetectionActivity.smali file. Let's open the file and find the condition check.
```bash
.line 39
    .local v5, "f":Ljava/io/File;
    invoke-virtual {v5}, Ljava/io/File;->exists()Z

    move-result v1

    .line 40
    if-eqz v1, :cond_0

    .line 42
    goto :goto_1

    .line 37
    .end local v5    # "f":Ljava/io/File;
    :cond_0
    nop

    .end local v4    # "files":Ljava/lang/String;
    add-int/lit8 v2, v2, 0x1

    goto :goto_0
```
Let's try to change the instruction if-eqz to if-nez this will make it check if the input is not equal to the values of file in files function which will return false. Then, we will recompile the edited code along with the resources and create a new APK file.
```bash
apktool b AndroGoat
I: Using Apktool 2.7.0
I: Checking whether sources has changed...
I: Smaling smali folder into classes.dex...
I: Checking whether resources has changed...
I: Building resources...
I: Copying libs... (/kotlin)
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk into: AndroGoat/dist/AndroGoat.apk
```
We will now sign in the generated apk with our own self-signed certificate so that the app can be installable in our device. First we generate a key.
```bash
keytool -genkey -keystore whoami.keystore -keyalg RSA -keysize 2048 -validity 1000 -alias whoami
Enter keystore password:  
Re-enter new password: 
Enter the distinguished name. Provide a single dot (.) to leave a sub-component empty or press ENTER to use the default value in braces.
What is your first and last name?
  [Unknown]:  
What is the name of your organizational unit?
  [Unknown]:  
What is the name of your organization?
  [Unknown]:  
What is the name of your City or Locality?
  [Unknown]:  
What is the name of your State or Province?
  [Unknown]:  
What is the two-letter country code for this unit?
  [Unknown]:  
Is CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown correct?
  [no]:  yes

Generating 2,048 bit RSA key pair and self-signed certificate (SHA384withRSA) with a validity of 1,000 days
        for: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
```
Once the key is generated we will sign in the apk
```bash
jarsigner -keystore whoami.keystore -verbose AndroGoat.apk whoami
```
We will get this output at the end of the file which shows that the process is successful
```bash
>>> Signer
    X.509, CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
    Signature algorithm: SHA384withRSA, 2048-bit key
    [trusted certificate]

jar signed.

Warning: 
The signer's certificate is self-signed.
```
Let's uninstall the first app before we install the new one.
```bash
adb uninstall owasp.sat.agoat
Success
```
```bash
adb install AndroGoat.apk
Performing Streamed Install
Success
```
Then boom the device is not rooted. There are better ways we can do this using tools such as frida which we will talk about later.

![img-description](3.png)