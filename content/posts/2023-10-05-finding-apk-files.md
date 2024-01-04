---
author: pl4int3xt
layout: post
title: Finding apk files
date: '2023-10-05 00:50:00 +0800'
cover: img/cover_images/22.png
description: "Learn how to find apk files for pentesting"
categories: [Android hacking 101, Intro to android hacking, Finding apk files]
tags: [Android, Apk]
---

# Finding apk files
Apk files can be found through various ways:
* Online: we can navigate to [apkcombo](https://apkcombo.com/) and search for a specific apk file and download it. There are many other sources but they might provide some dangerous apks so you should be careful
* Extracting the apk from the device: To extract an apk file you need to know the full path. Reading the content of /data/app/ is not permitted for non root users in android and thus it is difficult to guess the full package name of the app. Thats where we use the adb and pm which we learned from the adb blog.

This will list our package name which we want to locate in the device.
```bash
adb shell pm list packages | grep myapp
``` 
Once we get the package name, we type the following command to get the full path of the APK file.
```bash
adb shell pm path com.example.myapp
```
Finally, we can type the following command to retrieve the myapp.apk file.
```bash
adb pull /data/app/com.example.myapp-1/myapp.apk
```
There are other ways such as using third party apps so do your research 