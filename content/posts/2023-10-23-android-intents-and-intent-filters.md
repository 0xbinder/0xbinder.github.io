---
layout: post
title: Android Intents and Intent Filters
date: '2023-10-23 05:39:12 +0300'
image: /assets/img/cover_images/33.png
categories: [Android hacking 101, Android Intents and Intent Filters]
tags: [Intents, Intent Filters, ]
---

## Intents
An Intent is a messaging object you can use to request an action from another app component. They facilitate communication between components.
## Types of intents
### Explicit intents 
For explicit intents we have to explicitly provide the target app's package name or a fully-qualified component class name. here we use a fully-qualified component class name in our own app. 
```kotlin
Intent(applicationContext, MyActivity::class.java).also { intent ->
    startActivity(intent)
}
```
Here we provide the target app's package name to launch the main activity of the specified app
```kotlin
Intent(Intent.ACTION_MAIN).also { intent -> 
    intent.`package` = "com.google.android.youtube"
    startActivity(intent)
}
```
### Implicit intents
In implicit intents we do not specificy any components but we only declare a general action to be performed, android will then check for apps that can satisfy the intent and allow a user to choose. For example sending an email using implicit intent will allow a user to select apps that can handle the intent such as yahoo, gmail, messages, drive and others which are installed in the device
```kotlin
val intent = Intent(Intent.ACTION_SEND).apply {
    type = "text/plain"
    putExtra(Intent.EXTRA_MAIL, arrayOf("example@example.com"))
    putExtra(Intent.EXTRA_SUBJECT, "email subject")
    putExtra(Intent.EXTRA_TEXT, "email content")
}
startActivity(intent)
```
You need also to add this in the manifest file
```xml
<queries>
    <intent>
        <action android:name="android.intent.action.SEND"/>
        <data android:mimeType="text/plain">
    </intent>
</queries>
```
## Fundamental use cases of Intents
### Starting an activity
You can start a new instance of an Activity by passing an Intent to startActivity(). The Intent describes the activity to start and carries any necessary data. If you want to receive a result from the activity when it finishes, call startActivityForResult(). Your activity receives the result as a separate Intent object in your activity's onActivityResult() callback.
```kotlin
Intent(applicationContext, MyActivity::class.java).also { intent ->
    startActivity(intent)
}
```
```kotlin
val startForResult = registerForActivityResult(StartActivityForResult()) { result ->
    if (result.resultCode == Activity.RESULT_OK) {
        val intent = result.data
        // Handle the Intent
    }
}
startForResult.launch(Intent(this, ResultProducingActivity::class.java))
```
### Starting a service
You can start a service to perform a one-time operation (such as downloading a file) by passing an Intent to startService().
```kotlin
Intent(applicationContext, MyService::class.java).also { intent ->
    startService(intent)
}
```
### Delivering a broadcast
The system delivers various broadcasts for system events, such as when the system boots up or the device starts charging. You can deliver a broadcast to other apps by passing an Intent to sendBroadcast() or sendOrderedBroadcast().
```kotlin
Intent().also { intent ->
    intent.setAction("com.example.broadcast.MY_NOTIFICATION")
    intent.putExtra("data", "Notification data")
    sendBroadcast(intent)
}
```
## Intent Filters
To receive implicit intents in our app we specify the intent filters in our manifest file.Each intent filter specifies the type of intents it accepts based on the intent's action, data, and category. The system delivers an implicit intent to your app component only if the intent can pass through one of your intent filters. Inside the ```<intent-filter>```, you can specify the type of intents to accept using one or more of these three elements:
* ```<action>```
    Declares the intent action accepted, in the name attribute. The value must be the literal string value of an action, not the class constant.
* ```<data>```
    Declares the type of data accepted, using one or more attributes that specify various aspects of the data URI (scheme, host, port, path) and MIME type.
* ```<category>```
    Declares the intent category accepted, in the name attribute. The value must be the literal string value of an action, not the class constant. 
For example, here's an activity declaration with an intent filter to receive an ACTION_SEND intent when the data type is an image:

```xml
<intent-filter>
    <action android:name="android.intent.action.SEND"/>
    <category android:name="android.intent.category.DEFAULT"/>
    <data android:mimeType="image/*"/>
</intent-filter>
```