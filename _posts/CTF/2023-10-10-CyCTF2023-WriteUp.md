---
title: "CyCTF 2023 Finals Mobile WriteUps"
classes: wide
header:
  teaser: /assets/images/CTF/CyCTF-Finals/cover.png
ribbon: BabyBlue
description: "Mobile WriteUps"
categories:
  - CTF WriteUps
toc: true
---
# Cyctf Finals 2023

## IOS Mobile Challenges 

### Iwallet Version 2
```
Description :-
They updated their wallet, and I forgot my secret, again!
```
To solve this challenge we need to recap how did we get the flag from **"IWallet Version 1 in QUAL"**. We found the flag in **PINviewController.init** function :-
<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IWallet2/1.png" />
</p>
<center><font size="3"> <u>Figure: </u> IWallet Version 1 Flag<u></u> </font></center>
<br>

ِAlso we used a ["Swift demangler"](https://github.com/LaurieWired/iOS_Reverse_Engineering) script in ghidra 

you can find the write up over ["here"](https://medium.com/@mohammadolimat/cyctf23-iwallet-mobile-challenge-writeup-6be123b3f0fa)

So after running the swift demangler script lets search for **"ini"** in the Symbol Tree window in ghidra :-

<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IWallet2/2.png" />
</p>
<center><font size="3"> <u>Figure: </u> Symbol Tree window<u></u> </font></center>
<br>

after searching for the function that corresponds to **PINviewController.init function in Version 1** in QUAl which is **secViewController.init**. there was two main things that were interesting for me when I analyzed the function to find the difference between both :-

-   First the xor operation found at the beginning of the function

<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IWallet2/3.png" />
</p>
<center><font size="3"> <u>Figure: </u> XOR<u></u> </font></center>
<br>


-   Second, the part that had the flag in Version 1, in Version 2 has a reference to an address that has a value :- 

<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IWallet2/4.png" />
</p>
<br>


Example the a value for the highlighted address **DAT_1000163ea** :- 

<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IWallet2/5.png" />
</p>
<br>

BUT THIS VALUE CAN NOT BE A PRINTABLE CHAR!!!

Lets get back a step to **secViewController.init** and search if any operation will be done to the value in **DAT_1000163ea** address for example :- 

<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IWallet2/6.png" />
</p>
<br>

We found that it is going to get its value from the xor operation and this will be for the rest of addresses so it is easy xor decryption and then the flag just we need to get the values that will be used in the xor operations and solve with simple python script :- 

```
byte_100016410 = [0x93,0x57,0xdf,0x72,0xf6,0x7c,0x26,0xea,0xc5,0x06,0x05,0x6e,0xac,0xe2,0x68,0x2f,0x29,0xe3,0x47,0xf6,0xea,0xa3,0x2a,0x8b,0x81,0xea,0x2a,0x42,0x7b,0xf8,0xa7,0x6d,0x7d,0x99,0xf6,0x05,0x15,0xec,0xc6,0x74,0x5b,0xe3,0x15,0x6b,0x51,0xce,0x38,0x58,0xb5,0x4f,0xfc,0xd2,0x06,0x73,0x95,0xab,0x28,0xf2,0xe4,0xb2,0x68,0x83,0xb6,0x32,0xa7,0xfb,0x56,0x5e,0xee,0x39,0xb3,0x27,0x62,0xdc,0xde,0xc8,0x2f,0xeb,0x53,0xd6,0xb4,0xb9,0xca,0x82,0x48,0x62,0xf4,0xe5,0xfd,0x56,0x5e,0x0d,0xbe,0x00,0xca,0xa9,0x38,0xf8,0x4d,0xbb,0x7f,0xd7,0xb2,0xaf,0x8b,0x0e,0x46,0x60,0xbe,0xf6,0xda,0xcd,0x9e,0xde,0x5a,0x81,0x9d,0x23,0xba,0x47,0x14,0x2e,0x22,0x4d,0x10,0x9b,0xae,0x77,0x4a,0x83,0xfb,0x34,0x24,0x41,0xc7,0x5d,0xbb,0x1e,0x6a,0x4c,0x97,0x8b,0x9c,0x12,0x37,0x9c,0x54,0xe1,0x43,0x0e,0x97,0x67,0x4a,0x5f,0x8d,0x16,0xa9,0x3d,0x12,0xdf,0x5f,0xb0,0x09,0x5d,0x0c,0x6c,0xd9,0xc0,0x74,0x02,0xef,0xda,0xbc,0x9e,0xfe,0x2e,0x80,0x62,0x47,0xde,0x89,0xc4,0xcc,0x74]

flag = []
byte_100016410[162] = byte_100016410[160] ^ 0x2D
byte_100016410[163] = byte_100016410[161] ^ 0xB0
byte_100016410[166] = byte_100016410[164] ^ 0x2D
byte_100016410[167] = byte_100016410[165] ^ 0x6C
byte_100016410[170] = byte_100016410[168] ^ 0x42
byte_100016410[171] = byte_100016410[169] ^ 2
byte_100016410[174] = byte_100016410[172] ^ 0x8B
byte_100016410[175] = byte_100016410[173] ^ 0x9E
byte_100016410[178] = byte_100016410[176] ^ 0xB8
byte_100016410[179] = byte_100016410[177] ^ 0x62
byte_100016410[182] = byte_100016410[180] ^ 0xB0
byte_100016410[183] = byte_100016410[181] ^ 0xC4
byte_100016410[2] = byte_100016410[0] ^ 0xE0
byte_100016410[3] = byte_100016410[1] ^ 0x57
byte_100016410[6] = byte_100016410[4] ^ 0x81
byte_100016410[7] = byte_100016410[5] ^ 0x7C
byte_100016410[10] = byte_100016410[8] ^ 0xB3
byte_100016410[11] = byte_100016410[9] ^ 6
byte_100016410[14] = byte_100016410[12] ^ 0xD8
byte_100016410[15] = byte_100016410[13] ^ 0xE2
byte_100016410[18] = byte_100016410[16] ^ 0x5C
byte_100016410[19] = byte_100016410[17] ^ 0xE3
byte_100016410[22] = byte_100016410[20] ^ 0x92
byte_100016410[23] = byte_100016410[21] ^ 0xA3
byte_100016410[26] = byte_100016410[24] ^ 0xE8
byte_100016410[27] = byte_100016410[25] ^ 0xEA
byte_100016410[30] = byte_100016410[28] ^ 0x13
byte_100016410[31] = byte_100016410[29] ^ 0xF8
byte_100016410[34] = byte_100016410[32] ^ 0x1A
byte_100016410[35] = byte_100016410[33] ^ 0x99
byte_100016410[38] = byte_100016410[36] ^ 0x73
byte_100016410[39] = byte_100016410[37] ^ 0xEC
byte_100016410[42] = byte_100016410[40] ^ 0x3E
byte_100016410[43] = byte_100016410[41] ^ 0xE3
byte_100016410[46] = byte_100016410[44] ^ 0x35
byte_100016410[47] = byte_100016410[45] ^ 0xCE
byte_100016410[50] = byte_100016410[48] ^ 0xD6
byte_100016410[51] = byte_100016410[49] ^ 0x4F
byte_100016410[54] = byte_100016410[52] ^ 0x64
byte_100016410[55] = byte_100016410[53] ^ 0x73
byte_100016410[58] = byte_100016410[56] ^ 0x49
byte_100016410[59] = byte_100016410[57] ^ 0xF2
byte_100016410[62] = byte_100016410[60] ^ 3
byte_100016410[63] = byte_100016410[61] ^ 0x83
byte_100016410[66] = byte_100016410[64] ^ 0xCD
byte_100016410[67] = byte_100016410[65] ^ 0xFB
byte_100016410[70] = byte_100016410[68] ^ 0xDF
byte_100016410[71] = byte_100016410[69] ^ 0x39
byte_100016410[74] = byte_100016410[72] ^ 0x52
byte_100016410[75] = byte_100016410[73] ^ 0xDC
byte_100016410[78] = byte_100016410[76] ^ 0x55
byte_100016410[79] = byte_100016410[77] ^ 0xEB
byte_100016410[82] = byte_100016410[80] ^ 0xCD
byte_100016410[83] = byte_100016410[81] ^ 0xB9
byte_100016410[86] = byte_100016410[84] ^ 0x7A
byte_100016410[87] = byte_100016410[85] ^ 0x62
byte_100016410[90] = byte_100016410[88] ^ 0xCE
byte_100016410[91] = byte_100016410[89] ^ 0x56
byte_100016410[94] = byte_100016410[92] ^ 0x8A
byte_100016410[95] = byte_100016410[93]
byte_100016410[98] = byte_100016410[96] ^ 0xD
byte_100016410[99] = byte_100016410[97] ^ 0xF8
byte_100016410[102] = byte_100016410[100] ^ 0x3E
byte_100016410[103] = byte_100016410[101] ^ 0xD7
byte_100016410[106] = byte_100016410[104] ^ 0xD8
byte_100016410[107] = byte_100016410[105] ^ 0xE
byte_100016410[110] = byte_100016410[108] ^ 0x9E
byte_100016410[111] = byte_100016410[109] ^ 0xF6
byte_100016410[114] = byte_100016410[112] ^ 0xC9
byte_100016410[115] = byte_100016410[113] ^ 0xDE
byte_100016410[118] = byte_100016410[116] ^ 0xCD
byte_100016410[119] = byte_100016410[117] ^ 0x23
byte_100016410[122] = byte_100016410[120] ^ 0x5D
byte_100016410[123] = byte_100016410[121] ^ 0x2E
byte_100016410[126] = byte_100016410[124] ^ 0x5E
byte_100016410[127] = byte_100016410[125] ^ 0x9B
byte_100016410[130] = byte_100016410[128] ^ 0x66
byte_100016410[131] = byte_100016410[129] ^ 0x83
byte_100016410[134] = byte_100016410[132] ^ 0x70
byte_100016410[135] = byte_100016410[133] ^ 0x41
byte_100016410[138] = byte_100016410[136] ^ 0xD7
byte_100016410[139] = byte_100016410[137] ^ 0x1E
byte_100016410[142] = byte_100016410[140] ^ 0xFA
byte_100016410[143] = byte_100016410[141] ^ 0x8B
byte_100016410[146] = byte_100016410[144] ^ 0x59
byte_100016410[147] = byte_100016410[145] ^ 0x9C
byte_100016410[150] = byte_100016410[148] ^ 0x2C
byte_100016410[151] = byte_100016410[149] ^ 0xE
byte_100016410[154] = byte_100016410[152] ^ 0x3A
byte_100016410[155] = byte_100016410[153] ^ 0x5F
byte_100016410[158] = byte_100016410[156] ^ 0xD8
byte_100016410[159] = byte_100016410[157] ^ 0x3D


flag.append(chr(byte_100016410[106]))
flag.append(chr(byte_100016410[14]))

flag.append(chr(byte_100016410[162]))

flag.append(chr(byte_100016410[70]))

flag.append(chr(byte_100016410[146]))

flag.append(chr(byte_100016410[34]))
flag.append(chr(byte_100016410[110]))

flag.append(chr(byte_100016410[90]))

flag.append(chr(byte_100016410[146]))

flag.append(chr(byte_100016410[50]))

flag.append(chr(byte_100016410[162]))

flag.append(chr(byte_100016410[82]))

flag.append(chr(byte_100016410[154]))

flag.append(chr(byte_100016410[174]))

flag.append(chr(byte_100016410[70]))

flag.append(chr(byte_100016410[74]))

flag.append(chr(byte_100016410[146]))

flag.append(chr(byte_100016410[110]))

flag.append(chr(byte_100016410[70]))

flag.append(chr(byte_100016410[98]))

flag.append(chr(byte_100016410[110]))

flag.append(chr(byte_100016410[146]))

flag.append(chr(byte_100016410[74]))

flag.append(chr(byte_100016410[174]))

flag.append(chr(byte_100016410[110]))

flag.append(chr(byte_100016410[90]))

flag.append(chr(byte_100016410[146]))

flag.append(chr(byte_100016410[74]))

flag.append(chr(byte_100016410[18]))

flag.append(chr(byte_100016410[34]))

flag.append(chr(byte_100016410[30]))

flag.append(chr(byte_100016410[166]))

print("".join(flag))
```

Flag :- 
cytctf{Str1ng_3ncryp710n_15_n07_3n0ugh!}



### IBank 

```
Description :- 
My bank released this version, but they took it down quickly. Could you please help figure out what were they hiding?
```

It is the same methodology as IWallet Version 2. After using swift demngler script we will search for **"ini"** in the symbol tree window to search for any initialized strings :- 

<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IBank/1.png" />
</p>
<center><font size="3"> <u>Figure: </u> Symbol Tree window<u></u> </font></center>
<br>

**variable_initialization_expression_of_LoginViewController.key** was the most sus as it looks like it is going to initialize a key and started to analyze :-

<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IBank/2.png" />
</p>
<center><font size="3"> <u>Figure: </u>key initialization<u></u> </font></center>
<br>

As we can see it is initializing a key with length of 0x14 (20 in decimal) starting from address **DAT_100011c90** -> 0x100011c90
So all we need is to get the values used in the xor operations the create a python script :- 

```
arr = [ 0xaf, 0x94, 0x22, 0x22, 0xd9, 0xf2, 0xad, 0x13, 0xf6, 0xe4, 0x7f, 0x05, 0x70, 0x3b, 0xec, 0x5d, 0xb8, 0x83, 0xb0, 0x00, 0x9d ]
out = []

out.append(chr(arr[0] ^ 0xfc))
out.append(chr(arr[1] ^ 0xf6))
out.append(chr(arr[2] ^ 0x58))
out.append(chr(arr[3] ^ 1))
out.append(chr(arr[4] ^ 0xee))
out.append(chr(arr[5] ^ 0x85))
out.append(chr(arr[6] ^ 0xda))
out.append(chr(arr[7] ^ 0x75))
out.append(chr(arr[8] ^ 0x9b))
out.append(chr(arr[9] ^ 0x93))
out.append(chr(arr[10] ^ 0x15))
out.append(chr(arr[11] ^ 0x69))
out.append(chr(arr[12] ^ 0x1d))
out.append(chr(arr[13] ^ 0x18))
out.append(chr(arr[14] ^ 0xdd))
out.append(chr(arr[15] ^ 0x7e))
out.append(chr(arr[16] ^ 0xf7))
out.append(chr(arr[17] ^ 0xb0))
out.append(chr(arr[18] ^ 0xd4))
out.append(chr(arr[19] ^ 0x70))
out.append(chr(arr[20] ^ 0x9d))

print("".join(out))
```

The Key :- Sbz#7wwfmwjlm#1#O3dp

So we need to run the IOS and enter the key to get the flag I used ["appetize.io"](https://appetize.io/) for simulation :- 

<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IBank/3.png" />
</p>
<center><font size="3"> <u>Figure: </u>appetize.io<u></u> </font></center>
<br>

Lets enter the key and get the Flag :-

<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IBank/4.png" />
</p>
<center><font size="3"> <u>Figure: </u>flag<u></u> </font></center>
<br>

Flag :- cyctf{Pay_4ttention_2_L0gs}

```
Both WriteUps for IWallet and IBank  was not the intended ways
```

### IBank Intended solution

First we will create account at ["appetize.io"](https://appetize.io/) for simulation. Then upload the given IBank app. We will Enable Debug Logs Before running the app :-

<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IBank/5.png" />
</p>
<center><font size="3"> <u>Figure: </u>Debug Logs<u></u> </font></center>
<br>

Then run the app and check carefully the logs :- 

<p align="center">
  <img src="/assets/images/CTF/CyCTF-Finals/Mobile/IBank/6.png" />
</p>
<center><font size="3"> <u>Figure: </u>The Key<u></u> </font></center>
<br>

The key found in the logs

Thats it, I hope you have enjoyed the writeup. If you have any question or comment please contact me.
