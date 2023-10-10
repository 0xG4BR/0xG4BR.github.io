---
title: "BlackHat MEA 2023 Reverse WriteUps"
classes: wide
header:
  teaser: /assets/images/CTF/BlackHat2023/BlackHat.png
ribbon: Blue
description: "BlackHat MEA 2023 WriteUps"
categories:
  - CTF WriteUps
toc: true
---


# BlackHat MEA 2023 Reverse Eng WriteUps

<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/BlackHat.png" />
</p>


## WhatAmI

It is a DLL file.I used PeStudio to get more information about the DLL file :- 

<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/WhatAmI/1.png" />
</p>
<center><font size="3"> <u>Figure: </u> SUS resource <u></u> </font></center>
<br>

After checking strings and didn't find any thing important so I checked the resource as it is colored orange and this means it is SUS and I found that it has a bitmap file

<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/WhatAmI/2.png" />
</p>
<center><font size="3"> <u>Figure: </u> BitMap File <u></u> </font></center>
<br>

So I opened it by Resource Hacker 

<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/WhatAmI/3.png" />
</p>
<center><font size="3"> <u>Figure: </u> Flag <u></u> </font></center>
<br>

FOUND THE FLAG!!!!

<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/WhatAmI/4.jpg" />
</p>
<br>

## Can you break the armor

I hade a python file which was obfuscated by Pyarmor.

<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/armor/6.png" />
</p>
<br>

- What is Pyarmor ?!
    - Pyarmor is a command line tool used to obfuscate python scripts, bind obfuscated scripts to fixed machine or expire obfuscated scripts.

So I had two approaches to solve this challenge: 

1- by using ltrace to intercept the dynamic library calls
2- By running the process and dumping the memory and getting strings from the dumped memory 

I solved by the second approach with the help of this article ["Reverse pyarmor obfuscated python script using memory dump technique"](https://medium.com/@liad_levy/reverse-pyarmor-obfuscated-python-script-using-memory-dump-technique-9823b856be7a)

NOTE
```
You need python 3.10 to run the challenge
```

So i used pdb python debugger to run the challenge so It doesn't terminates immediately and a can dump the memory:

MemoryDump.py (Got it from the above article)
```
# memdump.py
#https://gist.githubusercontent.com/Dbof/b9244cfc607cf2d33438826bee6f5056/raw/aa4b75ddb55a58e2007bf12e17daadb0ebebecba/memdump.py
#! /usr/bin/env python3
import sys
import re

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print('Usage:', sys.argv[0], '<process PID>', file=sys.stderr)
        exit(1)

    pid = sys.argv[1]

    # maps contains the mapping of memory of a specific project
    map_file = f"/proc/{pid}/maps"
    mem_file = f"/proc/{pid}/mem"

    # output file
    out_file = f'{pid}.dump'

    # iterate over regions
    with open(map_file, 'r') as map_f, open(mem_file, 'rb', 0) as mem_f, open(out_file, 'wb') as out_f:
        for line in map_f.readlines():  # for each mapped region
            m = re.match(r'([0-9A-Fa-f]+)-([0-9A-Fa-f]+) ([-r])', line)
            if m.group(3) == 'r':  # readable region
                start = int(m.group(1), 16)
                end = int(m.group(2), 16)
                mem_f.seek(start)  # seek to region start
                print(hex(start), '-', hex(end))
                try:
                    chunk = mem_f.read(end - start)  # read region contents
                    out_f.write(chunk)  # dump contents to standard output
                except OSError:
                    print(hex(start), '-', hex(end), '[error,skipped]', file=sys.stderr)
                    continue
    print(f'Memory dump saved to {out_file}')
```

So lets run the challenge :-
<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/armor/1.png" />
</p>
<br>
Now we need to run it until the obfuscated code is loaded to the memory.

Now lets get the PID and dump the memory using the MemoryDump.py code :- 

<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/armor/3.png" />
</p>
<br>

Now Dump the Memory of the process:- 

<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/armor/4.png" />
</p>
<br>

Lets search for the flag format at the memdump strings :- 

<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/armor/5.png" />
</p>
<br>

## Light up the Server

The challenge description:- 
```
We found this web server but we can't seem to retrieve any files from the server with a get request. to submit, wrap flag in BHFlagY{}.
```

We have got an ELF file called server ,config file and tmp folder that has flag.txt says "YAY you got the Flag" 

So lets load the server to IDA and run CAPA plugin and see if there is anything interesting:- 

<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/Server/1.png" />
</p>
<br>

The most interesting one is *Contain Obfuscated StackString*
Lets analyze the SUS Function that has Obfuscated StackString:-

<p align="center">
  <img src="/assets/images/CTF/BlackHat2023/Server/2.png" />
</p>
<br>


as you can see we have a regx expression :- 

**^([a-z]?[^a-e,g-z])la[g]{(h)0(s)t_\2(e)4d\4(r([_]?[^a-z]))(!)n((j(3))cti0)n(_)1s\6{1}5up3\5c3wl}**

By using the [regex101](https://regex101.com/) website we got the flag

The Flag :- flag{h0st_he4der_!nj3cti0n_1s_5up3r_c3wl}

