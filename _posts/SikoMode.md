---
title: "SikoMode"
classes: wide
header:
  teaser: /assets/images/site-images/SikoMode.jpg
ribbon: Blue
description: "It is one of the challenges in the practial malware analysis TCM course"
categories:
  - Malware Analysis
toc: true
---


Challenge:SikoMode
==================

[![Mohammed Gabr](https://miro.medium.com/v2/resize:fill:88:88/1*0-zFZAlkHHqav5kY3-W3Tw.jpeg)

](https://medium.com/@mohammedgabr.ex.g7b?source=post_page-----452715788d17--------------------------------)

[Mohammed Gabr](https://medium.com/@mohammedgabr.ex.g7b?source=post_page-----452715788d17--------------------------------)

┬À

[Follow](https://medium.com/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fsubscribe%2Fuser%2F7d55bd1d3c4&operation=register&redirect=https%3A%2F%2Fmedium.com%2F%40mohammedgabr.ex.g7b%2Fchallenge-sikomode-452715788d17&user=Mohammed+Gabr&userId=7d55bd1d3c4&source=post_page-7d55bd1d3c4----452715788d17---------------------post_header-----------)

5 min read┬ÀJun 18

\--

Listen

Share

This is the second challenge in PMA(Practical Malware Analysis) course at TCM Academy. You can download the sample used :-

[

PMAT-labs/labs/2-3.Challenge-SikoMode at main ┬À HuskyHacks/PMAT-labs
--------------------------------------------------------------------

### Labs for Practical Malware Analysis & Triage. Contribute to HuskyHacks/PMAT-labs development by creating an account onÔÇª

github.com

](https://github.com/HuskyHacks/PMAT-labs/tree/main/labs/2-3.Challenge-SikoMode?source=post_page-----452715788d17--------------------------------)

We are provided with executable file ÔÇ£unknown.exeÔÇØ lets get ready to analyze the sample.

**Tools Used :-**
=================

1- Basic Analysis

*   File hashes
*   VirusTotal
*   FLOSS
*   PEStudio
*   PEView
*   Wireshark
*   Inetsim
*   Procmon

2- Advanced Analysis

*   Cutter
*   Debugger

Basic Static Analysis :-
========================

First thing to do is to analyze the strings in the executable:-

I used floss command

The most Important strings I found was :-

Looks like it is communicating with ÔÇ£_cdn.altimiter.localÔÇØ_ Domain with post parameter and we can see that it is written in Nim Language .Also What is cosmo.jpeg ÔÇ£MATTÔÇÖs CATÔÇØ Doing here?!

So lets get more information to know wats happening. So lets see if it is malicious or not by using Virus Total:-

Looks like it is Malicious

So IÔÇÖve decide to open PEStudio :-

64 Bit

LetÔÇÖs see if its packed or not so I used PEView :-

Looks Like its not packed as the virtual size is not much bigger than size of raw data.

Until now the information we have got is still not good enough to tell what is this malware doing. Lets go to basic dynamic analysis.

Basic Dynamic Analysis :-
=========================

So first of all lets run the malware without connecting to intetsim (internet simulator)

As you can see looks like it checks if it can connect to the internet otherwise it deletes itself.

So for the next step lets open wireshark to check the callback domain used by the malware to check for internet connectivity:-

First callback domain

After the malware checks that it is connected to internet it starts sending data using post parameter to the following links :-

exfiltrate data

Lets check procmon to see if there is any SUS activities done inside the machine :-

Looks like its doing something with cosmo.jpeg and it created a file called password that has ÔÇ£SikoModeÔÇØ inside but I couldnÔÇÖt find any persistence technique used.

Actually we have got lots of information but not enough as still we donÔÇÖt know what is being sent so lets go to the Advanced Analysis.

**Advanced Statice Analysis**
=============================

So I used cutter for this part. So first of all lets make sure that it is written by NIM.

nim language 64bit arch

So in nim the main is called NimMainInner after analyzing I found conditions where the malware checks for connection and either deletes itself if no internet or steal data if it is connected :-

After analyzing the ÔÇ£stealStuff\_\_sikomode\_130ÔÇØ function I found that RC4 encryption is used before sending data :-

So at that point I decided to stop static analysis and start dynamic analysis.

Advanced Dynamic Analysis
=========================

I used x64dbg . So we have four main functions used by the malware

1- checkKillSwitchURL\_\_sikomode\_25 -> which is used to check if it is connected to internet or not

2- unpackResources\_\_sikomode\_17 -> which creates the password file (unpacks the password file) in ÔÇ£C:\\Users\\Public\\ÔÇØ

3- stealStuff\_\_sikomode\_130 -> it opens cosmo.jpeg encode by base64 and encrypts it by RC4 then exfiltrate data

4- houdini\_\_sikomode\_51 -> it terminate the process and deletes the malware

Challenge Questions:
====================

1- What language is the binary written in?

*   Nim

2- What is the architecture of this binary?

*   64 bit

3- Under what conditions can you get the binary to delete itself?

*   When it is not connected to internet (canÔÇÖt create successful connection with [http://update.ec12-4-109-278-3-ubuntu20-04.local/](http://update.ec12-4-109-278-3-ubuntu20-04.local/))
*   When interrupted while exfiltrating data
*   After finishing exfiltrating data

4- Does the binary persist? If so, how?

*   No it does not

5- What is the first callback domain?

*   http://update.ec12-4-109-278-3-ubuntu20-04.local/

6- Under what conditions can you get the binary to exfiltrate data?

*   If it is connected to the first callback domain successfully

7- What is the exfiltration domain?

*   http://cdn.altimiter.local

8- How does exfiltration take place?

*   It encodes the content of cosmo.jpeg to base64 then encrypts it by RC4 then send the output using post parameter

9- What URI is used to exfiltrate data?

*   http://cdn.altimiter.local/feed?post=\[data\]

10- What type of data is exfiltrated (the file is cosmo.jpeg, but how exactly is the fileÔÇÖs data transmitted?)

*   It encodes the content of cosmo.jpeg to base64 then encrypts it by RC4 with ÔÇ£password.txtÔÇØ as key

11- What kind of encryption algorithm is in use?

*   RC4

12- What key is used to encrypt the data?

*   ÔÇ£SikoModeÔÇØ at password.txt

13- What is the significance of \`houdini\`?

*   Function that makes the malware deletes itself
