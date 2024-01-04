---
author: pl4int3xt
layout: post
title: FЯIDA - Method hooking
date: '2023-10-05 18:01:21 +0800'
cover: img/cover_images/18.png
description: "Learn how to use FЯIDA to hook methods in android applications and bypass security mechanisms"
categories: [Android hacking 101, Intro to android hacking, FЯIDA - Method hooking]
tags: [Android, Reverse Engineering, FЯIDA, Javascript, Hooking]
---

## FЯIDA - Method hooking
We saw how we used the universal ssl pinning bypass script to bypass ssl pinning. We will now make our own custom script to hook a method and change it's function in runtime to bypass root detection. We will use androgoat apk.

![img-description](/assets/img/apktool/1.png)

From the reverse engineering blog we saw the isRooted() function that checks whether the device is rooted. 

![img-description](/assets/img/apktool/2.png)

We will now change the function return type to always be false using this custom script.
```javascript
Java.perform(function () {
  // we create a javascript wrapper for RootDetectionActivity
  var RootDetectionActivity = Java.use('owasp.sat.agoat.RootDetectionActivity');
  // implement our function
  RootDetectionActivity.isRooted.implementation = function () {
    // console.log is used to report information back to us
    console.log("Inside isRooted() function...");
    // return false
    return false
  };
});
```

Let's run frida. Make sure you always run the server first before running the scripts to avoid getting errors.

```bash
frida -l custom_root_bypass.js -f owasp.sat.agoat -U
     ____
    / _  |   Frida 16.1.4 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at https://frida.re/docs/home/
   . . . .
   . . . .   Connected to Nexus 5 (id=127.0.0.1:6555)
Spawned `owasp.sat.agoat`. Resuming main thread!                        
[Nexus 5::owasp.sat.agoat ]-> Inside isRooted() function...
Inside isRooted() function...
```

We were able to bypass the Root detection. 

![img-description](/assets/img/apktool/3.png)

We can bypass any functions or manipulate them as long as we can reverse the apk and understand the functions and how they operate. 

## FRida scripsts
[https://codeshare.frida.re/@masbog/frida-android-unpinning-ssl/] (Bypassing SSL Pinning)
[https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/] (Bypassing SSL Pinning)
[https://gist.github.com/d3vilbug/41deacfe52a476d68d6f21587c5f531d] (Getting AES Keys)
[https://gist.github.com/pich4ya/0b2a8592d3c8d5df9c34b8d185d2ea35] (Bypassing root detection and RootBeer library)                                