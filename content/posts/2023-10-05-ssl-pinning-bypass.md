---
layout: post
title: SSL Pinning bypass
date: '2023-10-05 16:29:36 +0800'
cover: img/cover_images/19.png
description: "SSL pinning is a technique that helps to prevent MITM attacks by hardcoding the SSL/TLS certificate’s public key into the app, but we can bypass it using FЯIDA"
categories: [Android hacking 101, Intro to android hacking, Intercepting network traffic]
tags: [Android, Reverse Engineering, Burpsuite, https, SSL Pinning, FЯIDA]
---

## SSL Pinning bypass
SSL pinning is a technique that helps to prevent MITM attacks by hardcoding the SSL/TLS certificate’s public key into the app. This means that when the app or device communicates with the server, it will compare the server’s SSL/TLS certificate’s public key with the one that is hardcoded into the app or device. 

There are two techniques used in SSL Pinning:
* Certificate SSL pinning: SSL certificate pinnning technique involves hard-coding the SSL certificate of a server into the client’s application. The client then compares the server’s certificate with the hard-coded certificate and only allows communication if they match.
* Public key pinnign: Public key pinning involves hard-coding the public key of the server’s SSL certificate instead of the entire certificate. The client then checks that the server presents a certificate containing the same public key that was hard-coded into the client’s application.

Certificate pinning is easier to implement but may require frequent updates if the server’s certificate changes frequently. Public key pinning provides more flexibility in certificate management but requires more technical expertise to implement.

## Why do we need to bypass SSL Pinning
Almost all modern apps implement ssl pinning and hence we need to bypass their pinned certificate and use the burp certificate to intercept the https requests. This is the only way that we will be able to view and manipulate the requests through our burp proxy

## FЯIDA
[FЯIDA](https://frida.re/) is a Dynamic instrumentation toolkit for developers, reverse-engineers, and security researchers. We can take advantage of the tool to bypass ssl pinning, root detection, hook into both native and java functions and change their return types while the app is running and many more other cool stuff. Let's now install frida into our machine
```bash
pip install Frida
pip install frida-tools
```
Next we need to download the [server](https://github.com/frida/frida/releases/) that will be running inside our device. Check the architecture of your device using the following command
```bash
adb -e shell getprop ro.product.cpu.abi
x86_64
```
download one of these according to the architecture of your device.
```
frida-server-12.4.7-android-x86.xz
frida-server-12.4.7-android-x86_64.xz
```
push frida server into device
```bash
adb push ~/Downloads/frida-server /data/local/tmp
```
give frida server permissions
```bash
adb shell chmod 777 /data/local/tmp/frida-server
```
Open burp suite and navigate to proxy settings. Select Import/ Export CA certificate -> Certificate in Der format -> Next . Choose a file to export then export the file. Push the certificate to the device
```bash
adb push cacert.der /data/local/tmp/cert-der.crt
```
Run frida server
```bash
adb shell /data/local/tmp/frida-server &
```
List all running processes in device
```bash
frida-ps -aU
 PID  Name                               Identifier                          
----  ---------------------------------  ------------------------------------
3874  AndroGoat - Insecure App (Kotlin)  owasp.sat.agoat                     
2465  Google Play Store                  com.android.vending                 
2862  Phone                              com.android.dialer                  
4948  Yahoo Mail                         com.yahoo.mobile.client.android.mail
```
We need to locate our target application. We will bypass yahoo mail so we get the Identifier of yahoo mail
```bash
com.yahoo.mobile.client.android.mail
```
Next we need to find a script to bypass ssl pinning from frida. You can check the script from [here](https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/). There are many different scripts for different purposes.
```javascript
/* 
   Android SSL Re-pinning frida script v0.2 030417-pier 

   $ adb push burpca-cert-der.crt /data/local/tmp/cert-der.crt
   $ frida -U -f it.app.mobile -l frida-android-repinning.js --no-pause

   https://techblog.mediaservice.net/2017/07/universal-android-ssl-pinning-bypass-with-frida/
   
   UPDATE 20191605: Fixed undeclared var. Thanks to @oleavr and @ehsanpc9999 !
*/

setTimeout(function(){
    Java.perform(function (){
    	console.log("");
	    console.log("[.] Cert Pinning Bypass/Re-Pinning");

	    var CertificateFactory = Java.use("java.security.cert.CertificateFactory");
	    var FileInputStream = Java.use("java.io.FileInputStream");
	    var BufferedInputStream = Java.use("java.io.BufferedInputStream");
	    var X509Certificate = Java.use("java.security.cert.X509Certificate");
	    var KeyStore = Java.use("java.security.KeyStore");
	    var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
	    var SSLContext = Java.use("javax.net.ssl.SSLContext");

	    // Load CAs from an InputStream
	    console.log("[+] Loading our CA...")
	    var cf = CertificateFactory.getInstance("X.509");
	    
	    try {
	    	var fileInputStream = FileInputStream.$new("/data/local/tmp/cert-der.crt");
	    }
	    catch(err) {
	    	console.log("[o] " + err);
	    }
	    
	    var bufferedInputStream = BufferedInputStream.$new(fileInputStream);
	  	var ca = cf.generateCertificate(bufferedInputStream);
	    bufferedInputStream.close();

		var certInfo = Java.cast(ca, X509Certificate);
	    console.log("[o] Our CA Info: " + certInfo.getSubjectDN());

	    // Create a KeyStore containing our trusted CAs
	    console.log("[+] Creating a KeyStore for our CA...");
	    var keyStoreType = KeyStore.getDefaultType();
	    var keyStore = KeyStore.getInstance(keyStoreType);
	    keyStore.load(null, null);
	    keyStore.setCertificateEntry("ca", ca);
	    
	    // Create a TrustManager that trusts the CAs in our KeyStore
	    console.log("[+] Creating a TrustManager that trusts the CA in our KeyStore...");
	    var tmfAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
	    var tmf = TrustManagerFactory.getInstance(tmfAlgorithm);
	    tmf.init(keyStore);
	    console.log("[+] Our TrustManager is ready...");

	    console.log("[+] Hijacking SSLContext methods now...")
	    console.log("[-] Waiting for the app to invoke SSLContext.init()...")

	   	SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").implementation = function(a,b,c) {
	   		console.log("[o] App invoked javax.net.ssl.SSLContext.init...");
	   		SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom").call(this, a, tmf.getTrustManagers(), c);
	   		console.log("[+] SSLContext initialized with our custom TrustManager!");
	   	}
    });
},0);
```
Next we need to hook the script to our target application. we use ```-l``` to specificy the path to our javascript payload, ```-f ``` to specificy our target to hook and ```-U ``` to specify that we are connecting using USB
```bash
frida -l ssl_pinning.js -f com.yahoo.mobile.client.android.mail -U
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
Spawned `com.yahoo.mobile.client.android.mail`. Resuming main thread!   
[Nexus 5::com.yahoo.mobile.client.android.mail ]->
[.] Cert Pinning Bypass/Re-Pinning
[+] Loading our CA...
[o] Our CA Info: CN=PortSwigger CA, OU=PortSwigger CA, O=PortSwigger, L=PortSwigger, ST=PortSwigger, C=PortSwigger
[+] Creating a KeyStore for our CA...
[+] Creating a TrustManager that trusts the CA in our KeyStore...
[+] Our TrustManager is ready...
[+] Hijacking SSLContext methods now...
[-] Waiting for the app to invoke SSLContext.init()...
[o] App invoked javax.net.ssl.SSLContext.init...
[+] SSLContext initialized with our custom TrustManager!
[o] App invoked javax.net.ssl.SSLContext.init...
[+] SSLContext initialized with our custom TrustManager!
```

We are now able to intercept network traffic from yahoo. 

![img-description](/assets/img/frida/1.png)

We can now use frida to bypass root detection the same way we did to bypass ssl pinning. To multiple bypass you just need to put multiple scripts in one file and run it.