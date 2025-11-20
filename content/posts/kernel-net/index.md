---
author: 0xbinder
layout: post
title: Kernel Net
date: '2025-11-11'
description: "A in-kernel prototype inference engine for hosting mysterious models."
useRelativeCover: true
categories: [Mobile Hacking Lab]
---

![img-description](featured.png)


## Distribution files
The source code for the custom kernel driver, kernel commit hash, debug kernel and corellium kernel along with vmlinux has been provided in the attachment.

[Kern-net.zip](https://weurope1.blob.core.windows.net/kernel/kern-net.zip)

Debug environment credentials:
- Unprivileged user : mhl:hacker
- Privileged user      : root:toor
## Objective

Your goal is to escalate your privileges and obtain the flag located at /data/vendor/secret/flag.txt.

## Sidenote
The debug environment was built to closely mirror the Corellium device, excluding SELinux. Validate your exploit against the debug environment first; port it to the Corellium device only after successful validation on debug environment.


we have a `run.sh`

```bash
qemu-system-aarch64 \
  -machine virt \
  -cpu cortex-a55 \
  -nographic -smp 2 \
  -hda ./rootfs.ext2 \
  -kernel ./Image \
  -append "console=ttyAMA0 root=/dev/vda nokaslr quiet" \
  -m 2048 \
  -net user,hostfwd=tcp::10023-:22 -net nic \
  -s
```

we can run the image and use the credentials provided

```bash
./run.sh 
WARNING: Image format was not specified for './rootfs.ext2' and probing guessed raw.
         Automatically detecting the format is dangerous for raw images, write operations on block 0 will be restricted.
         Specify the 'raw' format explicitly to remove the restrictions.
Seeding 2048 bits and crediting
Saving 2048 bits of creditable seed for next boot
Starting syslogd: OK
Starting klogd: OK
Running sysctl: OK
Starting network: OK
Starting dhcpcd...
dhcpcd-9.4.1 starting
DUID 00:01:00:01:2f:9a:46:01:52:54:00:12:34:56
no interfaces have a carrier
forked to background, child pid 140
Starting sshd: OK

Hack The Planet!!!
mobile-hacking-lab login: mhl
Password: 
$ whoami
mhl
$ 
```
check if module is loaded

```bash
$ ls -la /dev/kern-net
crw-r--r--    1 root     root      236,   0 Jan  1  1970 /dev/kern-net
$  cat /proc/devices | grep kern-net
236 kern-net
```
test driver first 

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>

#define DEVICE_PATH "/dev/kern-net"
#define LOAD_MODEL_DATA 0x1337
#define RUN_MODEL       0x1338

struct model_metadata {
   uint32_t framework_type;
   uint16_t model_version;
   uint16_t precision_bits;
   uint32_t input_shape[3];
   uint32_t output_size;
   uint64_t weight_checksum;
   char model_desc[96];
} __attribute__((packed));

int main() {
    int fd;
    struct model_metadata meta;
    
    printf("[*] Opening device %s\n", DEVICE_PATH);
    fd = open(DEVICE_PATH, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    
    // Test with valid data first
    memset(&meta, 0, sizeof(meta));
    meta.framework_type = 1;  // TensorFlow
    meta.model_version = 1;
    meta.precision_bits = 32;
    meta.input_shape[0] = 224;
    meta.input_shape[1] = 224;
    meta.input_shape[2] = 3;
    meta.output_size = 1000;
    meta.weight_checksum = 0xdeadbeef;
    strcpy(meta.model_desc, "Test Model");
    
    printf("[*] Sending valid LOAD_MODEL_DATA\n");
    if (ioctl(fd, LOAD_MODEL_DATA, &meta) < 0) {
        perror("ioctl");
        close(fd);
        return 1;
    }
    
    printf("[+] Valid request successful\n");
    close(fd);
    return 0;
}
```
Compile the binary statically to avoid GLIBC version error

```bash
aarch64-linux-gnu-gcc -static -o test test.c
```
copy the binary to our machine

```bash
  scp -P 10023 test mhl@localhost:/tmp/
```
The tests works well and we are able to send a valid request successfully

```bash
$ ./test
[*] Opening device /dev/kern-net
[*] Sending valid LOAD_MODEL_DATA
[+] Valid request successful
$ 
```

## Vulnerability Analysis
The bug is in the `LOAD_MODEL_DATA` case of `knet_ioctl()`:

```c
strcpy(mdata->model_desc, user_data->model_desc);
```

This is a stack buffer overflow vulnerability because:

* `user_buffer[0x500]` is allocated on the stack
* `user_data->model_desc` is at an offset within this buffer (96 bytes based on the struct)
* `strcpy()` has no bounds checking - it copies until it hits a null terminator
* An attacker can provide a `model_desc` longer than 96 bytes, overflowing the `mdata->model_desc` buffer

Since `mdata` is allocated with `kmalloc()`, overflowing `model_desc` will corrupt heap metadata or adjacent kernel objects.

```c
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/random.h>

#define DEVICE_NAME "kern-net"
#define CLASS_NAME "MobileHackingLab"

#define LOAD_MODEL_DATA 0x1337
#define RUN_MODEL       0x1338

struct model_metadata {
   uint32_t framework_type;    // 1=TensorFlow, 2=PyTorch, 3=ONNX
   uint16_t model_version;     // Model version number
   uint16_t precision_bits;    // 8, 16, 32 bit precision
   uint32_t input_shape[3];    // [height, width, channels] or [sequence, features, 0]
   uint32_t output_size;       // Number of output neurons/classes
   uint64_t weight_checksum;   // CRC64 of model weights
   char model_desc[96];        // Model description
} __packed;

struct model_metadata* mdata;

static int major;
static struct class* knet_class = NULL;
static struct device* knet_device = NULL;

static long knet_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    long ret = -1;
    char user_buffer[0x500] = {0};

    switch (cmd) {
      case LOAD_MODEL_DATA: {
        struct model_metadata* user_data = (struct model_metadata*)&user_buffer;
        
        ret = copy_from_user(user_data, (char __user *)arg, sizeof(struct model_metadata));
        if (ret)
          goto leave;


        if (user_data->framework_type == 0 || user_data->framework_type > 3) {
          printk(KERN_ERR "[kern-net] Invalid framework type %u\n", user_data->framework_type);
          goto leave;
        }
        
        if (user_data->precision_bits != 8 && user_data->precision_bits != 16 && user_data->precision_bits != 32) {
          printk(KERN_ERR "[kern-net] Unsupported precision %u bits\n", user_data->precision_bits);
          goto leave;
        }

        mdata = kmalloc(sizeof(struct model_metadata), GFP_KERNEL_ACCOUNT);
        if (mdata <= 0)
          goto leave;

        mdata->framework_type = user_data->framework_type;
        mdata->model_version = user_data->model_version;
        mdata->precision_bits = user_data->precision_bits;
        memcpy(mdata->input_shape, user_data->input_shape, sizeof(mdata->input_shape));
        mdata->output_size = user_data->output_size;
        mdata->weight_checksum = user_data->weight_checksum;

        strcpy(mdata->model_desc, user_data->model_desc);

        ret = 0;
        break;
      }
      
      case RUN_MODEL:
        printk(KERN_INFO "[kern-net] Feature unsupported yet\n");
        break;
      
      default:
        printk(KERN_ERR "[kern-net]  Invalid command\n");
    }

leave:
    return ret;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = knet_ioctl,
};

static int __init knet_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
        printk(KERN_ALERT "[kern-net] Failed to register char device\n");
        return major;
    }

    knet_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(knet_class)) {
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "[kern-net] Failed to create class\n");
        return PTR_ERR(knet_class);
    }

    knet_device = device_create(knet_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(knet_device)) {
        class_destroy(knet_class);
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "[kern-net] Failed to create device\n");
        return PTR_ERR(knet_device);
    }

    printk(KERN_INFO "[kern-net] Module loaded: /dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit knet_exit(void) {
    device_destroy(knet_class, MKDEV(major, 0));
    class_unregister(knet_class);
    class_destroy(knet_class);
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "[kern-net] Module unloaded\n");
}

module_init(knet_init);
module_exit(knet_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hack the Kernel");
MODULE_DESCRIPTION("Hack All the Kernels");
```