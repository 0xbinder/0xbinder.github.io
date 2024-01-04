---
author: pl4int3xt
layout: post
title: Getting started with android hacking
date: '2023-10-04 20:52:04 +0800'
cover: img/cover_images/1.png
description: "Android is a Linux-based open source platform developed by the Open handset Alliance (a consortium lead by Google), which serves as a mobile operating system (OS)"
categories: [Android hacking 101, Intro to android hacking]
tags: [Android]
---

## Getting started with android hacking
Android is a Linux-based open source platform developed by the Open handset Alliance (a consortium lead by Google), which serves as a mobile operating system (OS). At its core, the operating system is known as Android Open Source Project (AOSP). The following are the major components of android.

![img-description](/assets/img/intro-to-android-hacking/android.png)

### The Linux Kernel
Android runtime relies on the the Linux kernel for underlying functionalities such as threading and low-level memory management.
### Hardware abstraction layer (HAL)
Think of HAL as a bridge between Android operating system and the hardware components. They provide standard interfaces that expose device hardware capabilities such as the sensors, camera, bluetooth, audio and other more to the higher-level Java API framework. Devices running Android 8.0 and above must support HALs written in the HAL Interface Definition Language (HIDL). HIDL is a language similar to C.
Android 11 also introduces support for HALs written in the Android Interface Definition Language (AIDL).
### Android runtime
Android runtime (ART) is the managed runtime used by applications and some system services on Android. For devices running Android version 5.0 (API level 21) or higher, each app runs in its own process and with its own instance of the Android Runtime (ART). ART runs multiple virtual machine for each application on low memory devices by executing Dalvik Executable format (DEX) files. The main features of ART are 
* Ahead-of-time (AOT) compilation
* Improved garbage collection
* Development and debugging improvements
* Improved diagnostic detail in exceptions and crash repor

### Native C/C++ libraries
The ART and HAL, are built from native code that requires native libraries written in C and C++. The Android platform provides Java framework APIs to expose the functionality of some of these native libraries to apps. For example, you can access OpenGL ES through the Android framework’s Java OpenGL API to add support for drawing and manipulating 2D and 3D graphics in your app. The Android NDK can be used to access some of these native platform libraries directly from your native code. 
### Java API framework
The entire feature-set of the Android OS is available to you through APIs written in the Java language. These APIs form the building blocks you need to create Android apps by simplifying the reuse of core, modular system components and services, which include the following:
* A rich and extensible view system you can use to build an app’s UI, including lists, grids, text boxes, buttons, and even an embeddable web browser
* A resource manager, providing access to non-code resources such as localized strings, graphics, and layout files
* A notification manager that enables all apps to display custom alerts in the status bar
* An activity manager that manages the lifecycle of apps and provides a common navigation back stack
* Content providers that enable apps to access data from other apps, such as the Contacts app, or to share their own data
### System apps
Android comes with a set of system apps for email, SMS messaging, calendars, internet browsing, contacts, and more. The developers can invoke these apps instead of recreating their own functionalities themeselves.

## Android Application Components
The application components are the essential blocks of and Android app. Each has a distinct life cycle.

### Activity
It represents a single screen with a UI. For example a chat app might have an activity that shows a list of chats, another activity to compose a chat and other activities for specific tasks.

### Service
A service allows an app to run in background without a user interface to perform long running operations or to perform work for remote processes. THere are to types of services
* Started services tell the system to keep them running until their work is completed. This might be to sync some data in the background or play music even after the user leaves the app. 
* Bound services run because some other app (or the system) has said that it wants to make use of the service. A bound service provides an API to another process, and the system knows there is a dependency between these processes. So if process A is bound to a service in process B, the system knows that it needs to keep process B and its service running for A.

### Broadcast Receiver
A broadcast receiver is a component that lets the system deliver events to the app outside of a regular user flow so the app can respond to system-wide broadcast announcements. Because broadcast receivers are another well-defined entry into the app, the system can deliver broadcasts even to apps that aren't currently running.
So, for example, an app can schedule an alarm to post a notification to tell the user about an upcoming event. Because the alarm is delivered to a BroadcastReceiver in the app, there is no need for the app to remain running until the alarm goes off.
Many broadcasts originate from the system, like a broadcast announcing that the screen is turned off, the battery is low, or a picture is captured. Apps can also initiate broadcasts, such as to let other apps know that some data is downloaded to the device and is available for them to use. 

### Content Provider
A content provider manages a shared set of app data that you can store in the file system, in a SQLite database, on the web, or on any other persistent storage location that your app can access. Through the content provider, other apps can query or modify the data, if the content provider permits it.
For example, the Android system provides a content provider that manages the user's contact information. Any app with the proper permissions can query the content provider, such as using ```ContactsContract.Data```, to read and write information about a particular person. 

## Additional components
### Fragments
Represents a portion of user interface in an Activity.

### Intent
Intent activates three of the four component types: activities, services, and broadcast receivers. Intents bind individual components to each other at runtime. You can think of them as the messengers that request an action from other components, whether the component belongs to your app or another.

### The manifest file
Before the Android system can start an app component, the system must know that the component exists by reading the app's manifest file, AndroidManifest.xml. Your app declares all its components in this file, which is at the root of the app project directory.

### App resources
These include files such as images, audio files, and anything relating to the visual presentation of the app. For example, you can define animations, menus, styles, colors, and the layout of activity user interfaces with XML files. 

## Android package
an apk file is a archive file that contains the files needed by the application to run. it can be unpacked by the following command

```bash
unzip app_name.apk
```

```bash
AndroidManifest.xml
classes.dex
kotlin
META-INF
res
resources.arsc
```

* AndroidManifest.xml: A manifest file that describes the application's package name, activities, resources, version, etc.

* classes.dex:  Contains all the java classes in a dex (Dalvik Executable) file format, to be executed by the Android Runtime.

* lib: Contains native libraries with compiled code, for different device architectures.

* META-INF: Contains verification information that is generated when the app is signed.

* res: Contains predefined application resources, like XML files that define a state list of colors, user interface layout, fonts, values, etc. 

* resources.arsc: Contains precompiled resources. It holds information that will link the code to resources.

* Assets: Contains assets that developers bundle with the application, and can be retrieved by the AssetManager. These assets can be images, videos, documents, databases, etc.

## Tools for android pentesting

There are alot of tools for android pentesting but these are the most common ones which you'll mostly need and use.

* [Android Studio](https://developer.android.com/studio): A software used to develop android apps. To understand android applications you need to develop some applications.

* [Genymotion](https://www.genymotion.com/): You can use any android virtual device of your choice but genymotion is a good choice for a vitual rooted device.

* [Android SDK platform tools](https://developer.android.com/tools/releases/platform-tools): Android SDK Platform-Tools is a component for the Android SDK. It includes tools that interface with the Android platform, primarily adb and fastboot

* [JADX](https://github.com/skylot/jadx.git): Dex to Java decompiler, Command line and GUI tools for producing Java source code from Android Dex and Apk files

* [APKTOOL](https://apktool.org/): A tool for reverse engineering Android apk files

* [Burp Suite](https://portswigger.net/burp): A set of tools used for web applications penetration testing.

* [Frida](https://frida.re/): Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers.

* [Ghidra](https://ghidra-sre.org/): A software reverse engineering (SRE) suite of tools developed by NSA's Research Directorate in support of the Cybersecurity mission

* [Drozer](https://labs.withsecure.com/tools/drozer): Comprehensive security and attack framework for Android.

* [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF.git): Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.

