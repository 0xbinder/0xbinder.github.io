---
author: pl4int3xt
layout: post
title: Iris ctf 2024
date: '2024-01-06'
# cover: img/cover_images/48.png
description: "Iris ctf 2024"
categories: [Capture The Flag]
---
## Reverse Engineering
> Rune? What's that?
> Rune? Like the ancient alphabet?

We are provided with a main.go file and an encrypted the file

```go
package main

import (
	"fmt"
	"os"
	"strings"
)

var flag = "irisctf{this_is_not_the_real_flag}"

func init() {
	runed := []string{}
	z := rune(0)

	for _, v := range flag {
		runed = append(runed, string(v+z))
		z = v
	}

	flag = strings.Join(runed, "")
}

func main() {
	file, err := os.OpenFile("the", os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println(err)
		return
	}

	defer file.Close()
	if _, err := file.Write([]byte(flag)); err != nil {
		fmt.Println(err)
		return
	}
}
```

Let's break down the code. In Go, the `init()` is called automatically before the `main()` when a program starts.

```go
runed := []string{}
z := rune(0)
```
This line creates an empty dynamic list of strings called runed. A variable `z` with the value `0` as a Unicode code point.

```go
for _, v := range flag {
	runed = append(runed, string(v+z))
	z = v
}
flag = strings.Join(runed, "")
```
* This line starts a loop that iterates over each character `v` in the flag string.
* In each iteration, it takes the current character `v` from the flag, adds the value of `z` to it, converts the result to a string, and appends it to the runed slice.
* After appending the modified character, the current character `v` becomes the new value of `z` for the next iteration.
* After the loop, it joins all the modified characters in the runed slice into a single string, and assigns it back to the flag variable.

The othe part is not much important it's also self explanatory. Now let's reverse the process to decrypt the file.

```go
package main

import (
	"fmt"
	"io/ioutil"
	"strings"
)

func decryptFlag(encrypted string) string {
	runed := []string{}
	z := rune(0)

	for _, v := range encrypted {
		runed = append(runed, string(v-z))
		z = rune(v - z)
	}

	return strings.Join(runed, "")
}

func main() {
	fileContent, err := ioutil.ReadFile("new")
	if err != nil {
		fmt.Println(err)
		return
	}

	decryptedFlag := decryptFlag(string(fileContent))
	fmt.Println("Decrypted Flag:", decryptedFlag)
}
```
* The `decryptFlag()` initializes runed as an empty dynamic list
* variable `z` initialized to `rune(0)` which is just `0`.
* Iterates over each character `v` of the encrypted string, subtracts the current value of `z` from the Unicode code point of the character `v`, converts the result to a string, and appends it to the runed slice.
* Updates the value of `z` to the Unicode code point of the current character`v`for the next iteration.
* Joins the strings in the runed slice to form the decrypted string and returns it.

Let's Gopher the code and get the flag

```shell
~/Documents/irisctf/whats-a-rune$ go run decrypt.go
Decrypted Flag: irisctf{i_r3411y_1ik3_num63r5}Nw[rV
```

#### Why did Goku switch to Golang ?

![yay](golang.gif)