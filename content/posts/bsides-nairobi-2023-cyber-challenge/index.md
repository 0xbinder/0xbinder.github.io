---
author: pl4int3xt
layout: post
title: BSides Nairobi 2023 Cyber Challenge
date: '2023-11-04 12:46:04 +0300'
// cover: /img/cover_images/40.png
description: "Bsides Nairobi 2023 CTF"
categories: [Capture The Flag]
---
## Mobile
### Daily blatha
Every day blatha. One part here, another there.
#### You got all my journals? (150pts) 
Use frida to get the name of the app or any other way 
```bash
b3nj4h@arch ~> frida-ps -aU
 PID  Name               Identifier               
----  -----------------  -------------------------
6010  Email              com.android.email        
6386  Google Play Store  com.android.vending      
5402  Messaging          com.android.messaging    
5975  Phone              com.android.dialer       
5632  Superuser          com.genymotion.superuser 
6254  dailyblatha        com.bsidesnrb.dailyblatha
```
we spawn the firebase activity with activity manager 
```bash
am start -n com.bsidesnrb.dailyblatha/.firebaseActivity
Starting: Intent { cmp=com.bsidesnrb.dailyblatha/.firebaseActivity }
```
The app has insecure logging

![img-description](8.png)

We try to grep for BSidesNRB using logcat inside the AVD
```bash
logcat | grep -i BSidesNRB
```
and we get the first piece of the flag
```bash
11-04 06:52:19.517  6254  6254 D BSidesNRB: Value is: BSidesNBI{4ndro1d
```
Next we open the sqlite activity to spawn the database
```bash
am start -n com.bsidesnrb.dailyblatha/.sqliteActivity  
Starting: Intent { cmp=com.bsidesnrb.dailyblatha/.sqliteActivity }
```

![img-description](10.png)

The database is initialize we pull it since we know the name
```bash
adb pull /data/data/com.bsidesnrb.dailyblatha/databases/bsidesnrb.db
```
we use sqlite 3 to get the second flag
```bash
b3nj4h@arch > sqlite3 bsidesnrb.db
SQLite version 3.43.2 2023-10-10 12:14:04
Enter ".help" for usage hints.
sqlite> .tables
android_metadata  flag            
sqlite> select * from flag
   ...> ;
1|flag2|_db_m1sc0nf1gs
sqlite> 
```
We navigate to sharedPrefsActivity and find this

![img-description](9.png)

We decode the string and get the third part of the flag
```bash
b3nj4h@arch ~> echo XzRyM19kNG5nM3IwdXNzc30= | base64 -d
_4r3_d4ng3r0usss}
```
We now have the full flag
```
BSidesNBI{4ndro1d_db_m1sc0nf1gs_4r3_d4ng3r0usss}
```
### WatchDog
#### First method
We get this if statement in the decompiled code. Let's try changing it in the smali code to bypass the check

![img-description](11.png)

decompile the app with apk tool
```bash
apktool d watchdog.apk
```
From the decompiled app we know the package and the class

![img-description](12.png)

We navigate to smali > d > b.smali and locate the if statement

```bash
    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    const-string p1, "You cannot move right now, the light is red!!"

    .line 20
    .line 21
    invoke-static {v3, p1, v1}, Landroid/widget/Toast;->makeText(Landroid/content/Context;Ljava/lang/CharSequence;I)Landroid/widget/Toast;

    .line 22
    .line 23
    .line 24
    move-result-object p1
```

We change the if-eqz to if-nez 
```bash
    .line 17
    if-nez p1, :cond_0
```
We need to change extractNativeLibs to true in the manifest file to avoid any installation errors
```bash
android:extractNativeLibs="true"
```
Let's compile the apk again
```bash
apktool b watchdog
I: Using Apktool 2.8.1-dirty
I: Checking whether sources has changed...
I: Checking whether resources has changed...
I: Building resources...
I: Building apk file...
I: Copying unknown files/dir...
I: Built apk into: watchdog/dist/watchdog.apk
```
Next we need to sign the apk. Let's navigate to the location of the apk file
```bash
cd watchdog/dist/
```
We then generate a key
```bash
keytool -genkey -keystore whoami.keystore -keyalg RSA -keysize 2048 -validity 1000
-alias whoami
Enter keystore password:  
Re-enter new password: 
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

Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 1,000 days
	for: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
```
Lastly we sign our apk
```bash
jarsigner -keystore whoami.keystore -verbose watchdog.apk whoami
```
Make sure you get this at the end
```bash
>>> Signer
    X.509, CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
    Signature algorithm: SHA256withRSA, 2048-bit key
    [trusted certificate]

jar signed.

Warning: 
The signer's certificate is self-signed.
```
We unistall the old apk and install the new one
```bash
adb uninstall watchdog.apk
adb install watchdog.apk
```
We open the app and click the button. Finally we get the flag

![img-description](13.png)

#### Second method
We can use frida script to change the true variable to false using a custom script Thanks to madbit for the script 
```javascript
Java.perform(function () {
    var MainActivity = Java.use('com.bsidesnrb.watchdog.MainActivity');

    // Hook the onCreate method of MainActivity
    MainActivity.onCreate.overload('android.os.Bundle').implementation = function (bundle) {
        // Call the original onCreate method
        this.onCreate(bundle);

        // Attempt to modify the field directly, handle the case where the field might be obfuscated
        try {
            var f = MainActivity.class.getDeclaredField('f1258t');
            f.setAccessible(true);
            f.setBoolean(this, false);
            console.log('Field f1258t set to false successfully.');
        } catch (e) {
            console.log('Field f1258t not found. Attempting to find the obfuscated field name.');

            // If the field name is obfuscated, you might need to iterate over all fields and find the correct one by type
            var fields = MainActivity.class.getDeclaredFields();
            for (var i = 0; i < fields.length; i++) {
                var field = fields[i];
                if (field.getType().getName() === 'boolean') {
                    field.setAccessible(true);
                    field.setBoolean(this, false);
                    console.log('Field name: ' + field.getName() + ', Type: ' + field.getType().getName());
                    console.log('Obfuscated boolean field set to false successfully. Field name: ' + field.getName());
                    break;
                }
            }
        }
    };
});
```
We use frida to change the boolean to false
```bash
frida -l bypass -f com.bsidesnrb.watchdog -U
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
   . . . .   Connected to Pixel 2 (id=127.0.0.1:6555)
Spawned `com.bsidesnrb.watchdog`. Resuming main thread!                 
[Pixel 2::com.bsidesnrb.watchdog ]-> Field f1258t not found. Attempting to find the obfuscated field name.
Field name: t, Type: boolean
Obfuscated boolean field set to false successfully. Field name: t
```
We click move and we get the flag

![img-description](13.png)

### Whatslif3
Thou shall find what made him one with the world.
#### This took us out? (75pts) 
From the source code we see that the input should be a base64 decoded string check_guess
![img-description](3.png)
We get the string from resources and base64 decode it
```bash
b3nj4h@arch ~> echo QlNpZGVzTkJJe3RoaXNfZGlkbid0X2tpbGxfdGhlbX0= | base64 -d
BSidesNBI{this_didn't_kill_them}
```
We use the output as our input string and hit the submit button. We get the activity with this encoded string

![img-description](2.png)

We take the string and slap it in cyber chef and wait for it to do the magic. Boom there we go we get the flag `BSidesNRB{c4r3full_hubr1s_w1ll_t4k3_us_0u7}`


## Forensics
### Mystique
Start by analyzing this email.

#### Who is the sender of this email?  (25pts) 
cat the file and grep for the X-Sender
```bash
cat infected.eml | grep -i X-Sender
X-Sender: 2export@ekofood.com.tr
```
#### What is the md5sum of the email attachment? (25pts) 
Download the attachment with thunderbird and check the md5sum hash
```bash
md5sum Items\ list.doc
2dae57b509d72eb69166e9d48995e530
```
#### Without opening the attachment on your host machine, use an online sandbox like AnyRun to observe what happens when the document is opened. From your analysis, what CVE is associate with the attachment? (25pts)
Open the file with virus total and navigate to community you'll get the CVE from ANY_RUN

![img-description](5.png)

#### What malware family is likely associated with the attachment? (25pts) 
From the previous image we can see the malware family 
```
agenttesla
```

#### Take a look at the malware configuration. What is the c2 Domain address? (25pts) 
Navigate to behaviour and check under DNS resolution

![img-description](6.png)

#### In your opinion, what protocol do you suspect could have been leveraged on for potential exfiltration? (25pts) 
The malware uses port 587 which is an smtp protocol port

![img-description](7.png)
