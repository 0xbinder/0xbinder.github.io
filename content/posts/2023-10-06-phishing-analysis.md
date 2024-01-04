---
layout: post
title: Phishing Analysis
date: '2023-10-06 22:05:05 +0300'
image: /assets/img/cover_images/9.png
categories: [BTLO, Security Operations]
tags: [BTLO, Text Editor,URL2PNG, WHOIS, Thunderbird]
---

## Phishing Analysis
A user has received a phishing email and forwarded it to the SOC. Can you investigate the email and attachment to collect useful artifacts? 

## Who is the primary recipient of this email?
We open the .eml file and search To keyword to get the recipient

![img-description](/assets/img/phishing-analysis/3.png)

## What is the subject of this email?

From The image above we can see the subject of the email

![img-description](/assets/img/phishing-analysis/3.png)

## What is the date and time the email was sent?

Again from the same image we can see the date and time the email was sent

![img-description](/assets/img/phishing-analysis/3.png)

## What is the Originating IP?

For this question we search for IP keyword

![img-description](/assets/img/phishing-analysis/4.png)

## Perform reverse DNS on this IP address, what is the resolved host? (whois.domaintools.com)

Search for the sender ip on [whois](https://whois.domaintools.com) and you will get the resolve host

![img-description](/assets/img/phishing-analysis/5.png)

## What is the name of the attached file?

We open the file with thunderbird and we see the attached file

![img-description](/assets/img/phishing-analysis/6.png)

## What is the URL found inside the attachment?

We open the attachment and we find the url inside

![img-description](/assets/img/phishing-analysis/7.png)

## What service is this webpage hosted on?

From the url above we can see the site is hosted on blogspot

## Using URL2PNG, what is the heading text on this page? (Doesn't matter if the page has been taken down!)

We open the url with url2png and we find the heading text on the page

![img-description](/assets/img/phishing-analysis/8.png)