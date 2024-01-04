---
layout: post
title: Reverse engineering apk file
date: '2023-10-05 01:08:46 +0800'
cover: img/cover_images/21.png
description: "Reverse engineering apk files using JADX-GUI and understanding the files inside an apk files"
categories: [Android hacking 101, Intro to android hacking, Reverse engineering android apk file]
tags: [Android, Reverse Engineering, Jadx, Apktool]
---

## Reverse engineering android apk file
We can use JADX-GUI to reverse engineer our apk. We will be using androgoat for demonstration purpose. Open JADX and open the apk file and wait for it to decompile the file.
This will be the application structure after decompilation. 

![img-description](/assets/img/android-rev/1.png)

We can navigate through the files and the packages and see what is inside. Most of the packages and files are generated imports and they are not written by the developer of the application. To see the code written by the developer we need to move to Resources and open the Android manifest file. We can now see the package name and now we know where the code is.

![img-description](/assets/img/android-rev/2.png)

The manifest file contains information about all activities, permissions, broadcast receivers, content providers and more. Click on the main activity to navigate to main activity. 

![img-description](/assets/img/android-rev/3.png)

You can expand the package files to see all activities and open the main activity from there.

![img-description](/assets/img/android-rev/4.png)

In most of cases the code will be obfuscated.Obfuscation is the process of making the code difficult for humans to read. Android Studio uses ProGuard for code obfuscation.When obfuscating with ProGuard, all method names are replaced with letters like a, b, c, and so on. This way, it will be difficult for someone to understand the functionality of the app, and thus, it will partially protect it from reverse engineering. In Android Studio, code obfuscation is not enabled by default. To enable it you have to set the boolean variable minifyEnabled to true, in the build.gradle file.
```gradle
buildTypes{
    release{
        minifyEnabled true
        proguardFiles getDefaultProguardFile("proguard-android-optimize.txt")
    }
}
```
For more information you can read about the [rules](https://developer.android.com/studio/build/shrink-code)
By Doing this, we can reverse any APK file, in order to study the flow of the source code and change or bypass the intended functionality.