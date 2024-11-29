---
author: 0xbinder
layout: post
title: Android Debug Bridge
date: '2023-10-04'
description: "This a command-line tool that lets you communicate directly with android device from your machine."
categories: [Android hacking 101]
tags: [Android, ADB]
---

## Android Debug Bridge
This a command-line tool that lets you communicate directly with android device from your machine. It is a client-server tool that has the following components
* A client which runs on your pc and sends commands.
* A daemon(adbd) that runs as a background process on each device.
* A server which manages communication between the client and daemon. It runs on the host pc as a background process

It is included in the Android SDK platform Tools package and can also be downloaded using the command below in linux

```bash
sudo apt install adb
```
Once installed we can list the devices attached

```bash
adb devices -l
```

To send a command to a specific device from the list of attached device we use the following command 

```bash
adb -s device_name install hellowolrd.apk
```

This command will install helloworld.apk to a device specified. incase you have only one device available you might use the command below

```bash 
adb install helloworld.apk
```

You can also use -e option to send a command to an emulator or -d to send to hardware device

## Set up port forwarding
You can also port forward the requests to a different port on a device. The following example sets up forawarding of host port 3187 to device port 5555

```bash
adb forward tcp:3187 tcp:5555
```

## Push and pull files from a device
To copy files from a directory inside a device
```bash
adb pull remote local
```

To copy files to a directory inside a device
```bash
adb push local remote
```

example
```bash
adb push myfile.txt /sdcard/myfile.txt
```

## Issue shell commands
You can issue android shell commands using the following command

```bash
adb shell shell_command
```
example
```bash
adb shell ls /system/bin
```
You can also get a shell from the device by using the following command
```bash
$ adb shell 
shell@ $ 
```

## Activity manager
Inside the adb shell you can use the activity manager to perform some actions such as start an activity, force stop a process, broadcast an intent, modify the device screen properties and more

syntax
```bash
am command
```
You can issue a command without entering a remote shell
```bash
adb shell am start -a android.intent.action.VIEW
```
example
```bash
adb shell am start -n com.example.app/.MainActivity
```
This starts the mainactivity of example app. You can start any activity in the app by replacing it with the .MainActivity

You can read about all activity manager commands from [android](https://developer.android.com/tools/adb)

## Package manager
You can use package manager(pm) to perform actions and queries on app packages installed on device.

```bash
pm command
```
You can issue a command without entering a remote shell. This will uninstall the specified app
```bash
adb shell pm unistall com.example.app
```
To install a package
```bash
pm install path_to_package
```
To list all packages 
```bash
pm list packages
```
To list all users
```bash
pm list users
```
To print the path to a package
```bash
pm path package_name
```
You can read about all package manager commands from [android](https://developer.android.com/tools/adb)

## Device policy manager (dpm)
Helps you develop and test your device management apps
```bash
dpm command
```
available dpm commands from [android](https://developer.android.com/tools/adb)

## Take screenshot
```bash
screencap filename
```
example we take a screenshot and pull it
```bash
$ adb shell
shell@ $ screencap /sdcard/screen.png
shell@ $ exit
$ adb pull /sdcard/screen.png
```

## Record a video
```bash
screenrecord filename
```
example
```bash
$ adb shell
shell@ $ screenrecord --verbose /sdcard/demo.mp4
(press COntrol + C to stop)
shell@ $ exit
$ adb pull /sdcard/demo.mp4
```

To learn more about the Android debug bridge and tools [read this](https://developer.android.com/tools/adb)