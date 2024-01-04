---
author: pl4int3xt
layout: post
title: Android important directories
date: '2023-10-04 23:59:50 +0800'
cover: img/cover_images/23.png
description: "Understanding androids most important directories"
categories: [Android hacking 101, Intro to android hacking, Android Important Directories]
tags: [Android, Directories]
---

## Android Important Directories

The directories listed below are the most important directories in an Android device:

* /data/data: Contains all the applications that are installed by the user.

* /data/user/0: Contains data that only the app can access.

* /data/app: Contains the APKs of the applications that are installed by the user.

* /system/app: Contains the pre-installed applications of the device.

* /system/bin: Contains binary files.

* /data/local/tmp: A world-writable directory.

* /data/system: Contains system configuration files.

* /etc/apns-conf.xml: Contains the default Access Point Name (APN) configurations. APN is used in order for the device to connect with our current carrier’s network.

* /data/misc/wifi: Contains WiFi configuration files.

* /data/misc/user/0/cacerts-added: User certificate store. It contains certificates added by the user.

* /etc/security/cacerts/: System certificate store. Permission to non-root users is not permitted.

* /sdcard: Contains a symbolic link to the directories DCIM, Downloads, Music, Pictures, etc.

# Databases and shared prefs
The databases are stored into ```/data/data/com.example.demo/databases/ ``` after the app initializes them while the shared prefs are stored into ```/data/data/com.example.demo/shared_prefs/ ```
Storing any sensitive information in shared prefs can be dangerous if not encrypted. Using [EncryptedSharedPreferences](https://developer.android.com/reference/kotlin/androidx/security/crypto/EncryptedSharedPreferences.html) can be a good solution for that. Information such as theme settings are stored in shared prefs in clear text since they are not sensitive.
The databases can be open with sqlite3
```bash
sqlite /data/data/com.example.app/databases/database1.db
```
