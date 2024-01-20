<!-- ---
author: pl4int3xt
layout: post
title: Pwn 107 - Tryhackme
date: '2024-01-18'
description: "Beginner level binary exploitation challenges from Tryhackme"
categories: [Pwn 101]
tags: [binary exploitation, Tryhackme ]
---

The `main()` has a format string vulnerability at `printf(local_48);` and a buffer overflow at `read(0,local_28,0x200);`

```c
void main(void){
  long in_FS_OFFSET;
  char local_48 [32];
  undefined local_28 [24];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  banner();
  puts(&DAT_00100c68);
  puts(&DAT_00100c88);
  puts("You mailed about this to THM, and they responsed back with some questions");
  puts("Answer those questions and get your streak back\n");
  printf("THM: What\'s your last streak? ");
  read(0,local_48,0x14);
  printf("Thanks, Happy hacking!!\nYour current streak: ");
  printf(local_48);
  puts("\n\n[Few days latter.... a notification pops up]\n");
  puts(&DAT_00100db8);
  read(0,local_28,0x200);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

The `get_streak()` is where we need to return to to get our shell.

```c
void get_streak(void){
  long lVar1;
  long in_FS_OFFSET;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  puts("This your last streak back, don\'t do this mistake again");
  system("/bin/sh");
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

All the protections are enabled. So what we need to do is to leak the stack canary data and the dynamic base address using the string formats vulnerability.

```shell
pl4int3xt@archlinux ~/D/p/pwn107> checksec --file=pwn107.pwn107
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH	Symbols		FORTIFY	Fortified	Fortifiable	FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   74 Symbols	 No	pwn107.pwn107
```

Let's stack by leaking the canary value. First we need to know where the canary value is. Let's use radare.

```shell
[0x00000780]> pdf @main
            ; DATA XREF from entry0 @ 0x79d(r)
┌ 243: int main (int argc, char **argv, char **envp);
│           ; var int64_t canary @ rbp-0x8
│           ; var void *buf @ rbp-0x20
│           ; var char *format @ rbp-0x40
│           0x00000992      55             push rbp
│           0x00000993      4889e5         mov rbp, rsp
│           0x00000996      4883ec40       sub rsp, 0x40
│           0x0000099a      64488b042528.  mov rax, qword fs:[0x28]
│           0x000009a3      488945f8       mov qword [canary], rax
│           0x000009a7      31c0           xor eax, eax
```

we see the canary value is stored at `rbp-0x8` -->