---
author: pl4int3xt
layout: post
title: Lab - Secure Notes
date: '2024-05-22'
description: "Android Content Provider Challenge"
cover: 52.png
useRelativeCover: true
categories: [Mobile Hacking Lab]
---

## Introduction

Welcome to the Secure Notes Challenge! This lab immerses you in the intricacies of Android content providers, challenging you to crack a PIN code protected by a content provider within an Android application. It's an excellent opportunity to explore Android's data management and security features.

## Objective

Retrieve a PIN code from a secured content provider in an Android application.

## Skills Required

* Basic understanding of Android app development.
* Familiarity with Android's content provider system and content query methods.

Analyzing the `AndroidManifest.xml` file we notice that we have an exported content provider `com.mobilehackinglab.securenotes.SecretDataProvider` and `MainActivity` is also exported.

```xml
<provider android:name="com.mobilehackinglab.securenotes.SecretDataProvider" android:enabled="true" android:exported="true" android:authorities="com.mobilehackinglab.securenotes.secretprovider"/>
    <activity android:name="com.mobilehackinglab.securenotes.MainActivity" android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.MAIN"/>
            <category android:name="android.intent.category.LAUNCHER"/>
        </intent-filter>
    </activity>
```

This means we any app in the same device can launch `MainActivity` or query the content provider using `content://com.mobilehackinglab.securenotes.secretprovider` content URI.

```java

```

In the `MainActivity` we have a button that calls `querySecretProvider(enteredPin)` when clicked.

```java

```

The `querySecretProvider(enteredPin)` function queries the content provider with the selection `pin=enteredPin` and then reads the text in column `secret`.

```java

```

Analyzing `com.mobilehackinglab.securenotes.SecretDataProvider` we
have `onCreate()` method that reads `config.properties` values and base64 decodes then. 

```java

```

Another interesting method is `query()` that calls `decryptSecret()`. This implements AES encryption and the input pin is the decryption key.

```java

```

Since the content provider is exported and the pin is 4 digits only, we can bruteforce it with multiple PIN values until we find the correct one.

```shell
adb shell content query - uri content://com.mobilehackinglab.securenotes.secretprovider --where pin=2580
```