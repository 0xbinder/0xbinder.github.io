---
layout: post
title: Log Analysis - Compromised WordPress
date: '2023-10-07 18:07:51 +0300'
image: /assets/img/cover_images/5.png
categories: [BTLO, Incident Response]
tags: [BTLO, WordPress, Grep, Awk, Uniq, Sort, Cut, Cat]
---

## Log Analysis – Compromised WordPress
One of our WordPress sites has been compromised but we're currently unsure how. The primary hypothesis is that an installed plugin was vulnerable to a remote code execution vulnerability which gave an attacker access to the underlying operating system of the server. 

##  Identify the URI of the admin login panel that the attacker gained access to (include the token) (3 points) 

We use the following command to get the result
```bash
> cat access.log | cut -d '"' -f2 | sort | uniq
GET /%20wp-login.php%20/?itsec-hb-token=adminlogin HTTP/1.1
GET /%2e/wp-login.php?itsec-hb-token=adminlogin HTTP/1.1
GET /account%2ehtml HTTP/1.1
GET /account%2ephp HTTP/1.1
GET /adm%2ehtml HTTP/1.1
GET /adm%2ephp HTTP/1.1
GET /adm%2fadmloginuser%2ephp HTTP/1.1
GET /adm%2f HTTP/1.1
GET /adm%2findex%2ehtml HTTP/1.1
```

##  Can you find two tools the attacker used? (3 points) 

We filter out User-Agent from log entries
```bash
cat access.log | cut -d '"' -f6 | sort | uniq > log1.log
```
sqlmap

![img-description](/assets/img/log-analysis/1.png)

wpscan

![img-description](/assets/img/log-analysis/2.png)

##  The attacker tried to exploit a vulnerability in ‘Contact Form 7’. What CVE was the plugin vulnerable to? (Do some research!) (4 points) 

Simple google search and we get the [CVE-2020–35489](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35489)

##  What plugin was exploited to get access? (4 points) 

We use grep to get the plugins
```bash
cat access.log | grep "/plugins/" | cut -d '/' -f6 | sort | uniq > log2.log
```
Doing some research on all the plugins we find out Simple File List 4.2.2 was used and is vulnerable
![img-description](/assets/img/log-analysis/3.png)

##  What is the name of the PHP web shell file? (3 points) 

We check for entries with uploads then using awk to get the file with .php extension 
```bash
❯ cat access.log | grep "/uploads/" | awk '$7~/\.php/' | cut -d '"' -f2 | sort | uniq
GET /wp-content/uploads/simple-file-list/fr34k.php HTTP/1.1
POST /wp-content/uploads/simple-file-list/fr34k.php HTTP/1.1
```

##  What was the HTTP response code provided when the web shell was accessed for the final time? (3 points) 

We use tail since we are looking for the last entries
```bash
❯ tail access.log
172.21.0.1 - - [14/Jan/2021:07:46:42 +0000] "GET /wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.3.1 HTTP/1.1" 404 488 "http://172.21.0.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
172.21.0.1 - - [14/Jan/2021:07:46:42 +0000] "GET /wp-content/plugins/simple-file-list/css/eeStyles.css?ver=5 HTTP/1.1" 404 488 "http://172.21.0.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
172.21.0.1 - - [14/Jan/2021:07:46:42 +0000] "GET /wp-content/themes/kadence/assets/css/global.min.css?ver=1.0.11 HTTP/1.1" 404 488 "http://172.21.0.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
172.21.0.1 - - [14/Jan/2021:07:46:42 +0000] "GET /wp-content/themes/kadence/assets/css/header.min.css?ver=1.0.11 HTTP/1.1" 404 488 "http://172.21.0.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
172.21.0.1 - - [14/Jan/2021:07:46:42 +0000] "GET /wp-content/themes/kadence/assets/css/content.min.css?ver=1.0.11 HTTP/1.1" 404 488 "http://172.21.0.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
172.21.0.1 - - [14/Jan/2021:07:46:42 +0000] "GET /wp-content/themes/kadence/assets/css/footer.min.css?ver=1.0.11 HTTP/1.1" 404 488 "http://172.21.0.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
172.21.0.1 - - [14/Jan/2021:07:46:42 +0000] "GET /wp-content/plugins/simple-file-list/js/ee-head.js?ver=5 HTTP/1.1" 404 488 "http://172.21.0.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
172.21.0.1 - - [14/Jan/2021:07:46:44 +0000] "GET /hello-world/ HTTP/1.1" 404 488 "http://172.21.0.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
172.21.0.1 - - [14/Jan/2021:07:46:13 +0000] "GET /adminlogin HTTP/1.1" 404 489 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
172.21.0.1 - - [14/Jan/2021:07:46:52 +0000] "GET /YouShouldSeeThis.txt HTTP/1.1" 200 488 "http://172.21.0.4/" "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"
```