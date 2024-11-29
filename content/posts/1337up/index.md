---
author: 0xbinder
layout: post
title: 1337up
date: '2023-11-17'
# cover: featured.png
useRelativeCover: true
description: "1337up CTF 2023"
categories: [Capture The Flag]
---

## Encoding

> I have no idea what this message means, can you help me decipher it? 👨‍💻
Author: CryptoCat

Take the message and let cyber chef do the magic.

![img-description](1.png)

##  Flag Extraction
> They told me I just need to extract flag but I don't know what that means?!
Author: CryptoCat

We are provided with a zip file. We open the file and find more compressions. We continue opening the file until we find the flag.gif file. Let's try strings and grep for the flag. There we go
```bash
strings flag.gif | grep "INTIGRITI"
INTIGRITI{fl46_3x7r4c710n_c0mpl373}
```

## Over the Wire (part 1)
> I'm not sure how secure this protocol is but as long as we update the password, I'm sure everything will be fine 😊
Author: CryptoCat
{: .prompt-info }

The flag.zip file looks interesting let's try and find it

![img-description](3.png)

Next we save this file as flag.zip in RAW format

![img-description](4.png)

After opening the file it prompts us to enter a password and so we continue following the stream to see if we can get the password and here we go.

![img-description](5.png)

We check the password from FTP and try to open the file but we get incorrect password. From the previous message we have the hint ```update it accordingly```. So we try 2023 instead of 2022 and boom we are able to open the file

![img-description](2.png)

We read the content of the flag.txt and get the flag

```bash
cat flag.txt
INTIGRITI{1f_0nly_7h3r3_w45_4_53cur3_FTP}
```

## Over the Wire (part 2)
> Learning the lessons from the previous failed secure file transfer attempts, CryptoCat and 0xM4hm0ud found a new [definitely secure] way to share information 😊

Since CryptoCat and 0xM4hm0ud decided to use a more secure way we have to dig deeper. We Follow the stream and come across their first email conversation

![img-description](6.png)

We save the email file as email.ml using the RAW format and open the file with thunderbird. We find our cute cat file attachment and download it.

![img-description](7.png)

I tried to use some steganography tools but found nothing so i continued following the stream and found the second email.

![img-description](8.png)

I extracted the file again and opened it with Thunderbird and downloaded the attachment.

![img-description](9.png)

I checked the type of file and found out it was not a jpg but a png.

```bash
file image.jpg
image.jpg: PNG image data, 325 x 211, 8-bit/color RGBA, non-interlaced
```

We now have to change the file extension to png and use our favourite tool zsteg to check for any hidden message in the file and there we go.

```bash
zsteg image.png
imagedata           .. file: Tower/XP rel 2 object not stripped - version 258
b1,r,msb,xy         .. file: OpenPGP Public Key
b1,rgb,lsb,xy       .. text: "INTIGRITI{H1dd3n_Crypt0Cat_Purr}\n"
b1,rgba,lsb,xy      .. text: "YUY{UU[S3}"
b4,r,lsb,xy         .. text: "34TBEDVF"
b4,g,lsb,xy         .. text: "hwwhwfwVfVFwh"
b4,b,lsb,xy         .. text: "#\"3#!#2#EUDEeDvgdR\r"
b4,rgb,msb,xy       .. text: "O|\"(Bj(\n"
b4,bgr,msb,xy       .. text: "|L(B\"h\n*"
b4,rgba,lsb,xy      .. text: "?y/i?h?yOx?x?x?F"
b4,abgr,msb,xy      .. text: "o</<o|oz/z"
```
## Keyless
> My friend made a new encryption algorithm. Apparently it's so advanced, you don't even need a key!
Author: CryptoCat

>The code provided has an encrypt method.
>* This takes the ASCII value of the current character, multiplies it by 2, and then adds 10 to the result.
>* XOR (^) with 42 is performed on the result from step 1, and then 5 is added to the XOR result.
>* The result from step 2 is multiplied by 3, and then 7 is subtracted from the product.
>* XOR operation with 23 is performed on the result from step 3. 
>* The final encrypted character is converted back to a character using the chr function and added to the encrypted_message.
>* The process is repeated for each character in the input message. uhuh That's alot

 
```python
def encrypt(message):
    encrypted_message = ""
    for char in message:
        a = (ord(char) * 2) + 10
        b = (a ^ 42) + 5
        c = (b * 3) - 7
        encrypted_char = c ^ 23
        encrypted_message += chr(encrypted_char)
    return encrypted_message
```
>To decrypt the function we need to code our own decrypt function to reverse the process. 
>* We XOR with 23 on the ASCII value of the current character.
>* 7 is added to the result from step 1.
>* The result from step 2 is divided by 3.
>* 5 is subtracted from the result from step 3, and then XOR operation with 42 is performed. The result is converted to an integer.
>* 10 is subtracted from the result from step 4, and then the result is divided by 2. 
>* The final decrypted character is obtained by converting the result from step 5 to an integer and then to a character using the chr function. 
>* The character is added to the decrypted_message.The process is repeated for each character in the input encrypted_message.

```python
def decrypt(encrypted_message):
    decrypted_message = ""
    for char in encrypted_message:
        decrypted_char = ord(char) ^ 23
        c = decrypted_char + 7
        b = c / 3
        a = int(b - 5) ^ 42
        original_char = (a - 10) / 2
        decrypted_message += chr(int(original_char))
    print(decrypted_message)
    return decrypted_message

decrypted_flag = decrypt("ȽƻǇȽȉƃȽǇȽΑɥćʝʣāʹćʹɱāʝʹɩßʵɷ˧ʹʣāʹʣāééāɃʹć˫éāɃʹćɷɷ΅")
```
We run our code and we decrypt the content 
```bash
python3 decrypt.py
INTIGRITI{m4yb3_4_k3y_w0uld_b3_b3773r_4f73r_4ll}
```

## Obfuscation
> I think I made my code harder to read. Can you let me know if that's true?
Let's try and deobfuscate the code using any tools. You can use chatgpt. The code rquires a file as an input

We are provided with obfuscated C code and so we try and deobfuscate it using online tools such as chat gpt. We now have an hint of what the code does. It requires us to provide an argument of the output file

```c
int main(int argc, const char *argv[]) {
    char *data;
    char *output = NULL;
    FILE *file;

    if (argc != 2) {
        printf("Not enough arguments provided!");
        exit(-2);
    }

    file = fopen(argv[1], "r");
    if (file == NULL) {
        perror("Error opening file");
        return -2;
    }
```
We compile the code and pass the output file as the argument for the executable
```bash
gcc -o chall chall.c
./chall output
```
We retrive the content of the file and we get our flag
```bash
cat output
INTIGRITI{Z29vZGpvYg==}
```