# Whitehacks 2022

I participated in Whitehacks 2022, and here are the brief writeups for the simpler challenges. 

Harder cryptography challenges will have separate, more detailed writeups but will be listed in the table of contents for reference.

## Table of Contents
1. [Miscellaneous](#miscellaneous)
   1. [Read The RULES](#read-the-rules)
   2. [Sanity Check](#sanity-check)
   3. [Catch the theiFS](#catch-the-theifs)
   4. [Never Gonna Stitch You Up](#never-gonna-stitch-you-up)
   5. [Escape Plane](#escape-plane)
   6. [Garbage Runner](#garbage-runner)
2. [Forensics](#forensics)
   1. [The Prompt Within](#the-prompt-within)
   2. [Jack's Rival](#jacks-rival)
   3. [Do the Shimmy!](#do-the-shimmy)
3. [Reverse Engineering](#reverse-engineering)
   1. [the floor is java](#the-floor-is-java)
4. [Cryptography](#cryptography)
   1. [Really S1mp(l3) Algorithm](#really-s1mpl3-algorithm)
   2. [The Indecipherable Cipher](#the-indecipherable-cipher)
   3. [The Poem of Knowledge](#the-poem-of-knowledge)
   4. [Ridiculously Simpler Algorithm](#ridiculously-simpler-algorithm)
   5. [Meet where? Middle Road?](meetwheremiddleroad.md)
   6. (CSIT) [Foil the Plot](foiltheplot.md)
   7. [Booleancrypt](booleancrypt.md)



## Miscellaneous
### Read the RULES
In #rules:
![image](https://user-images.githubusercontent.com/26357716/160151956-721e4d75-9298-4dde-ac26-a3d2ca4372d9.png)

[SHA1 online](http://www.sha1-online.com/) of `10: Observe CTF ethics. Observe all the usual rules for a Capture-The-Flag competition. This includes, but not limited to, strictly no sharing of flags and attacking the CTF's infrastructure.` gives the flag `WH2022{e47c05168af4eb9b47b8e0ebd357d2c35df4f062}`

### Sanity Check
![image](https://user-images.githubusercontent.com/26357716/160152982-525d0204-7692-478c-88e6-788f5412e68e.png)

`WH2022{w3lc0m3_t0_wh2022}`

### Catch the theiFS
Simple File System navigation: use `../` to move to parent, `{folder_name}/` to move to folder `{folder_name}`, `/` to start at the root

`WH2022{Low_crime_is_not_no_crime!}`

### Never Gonna Stitch You Up
[get_rickrolled.mp4](https://user-images.githubusercontent.com/26357716/160154656-ffc08247-0022-427e-a25c-d0a8b2c6c8c5.mp4)

`strings get_rickrolled.mp4 | grep "WH2022"` --> `WH2022{5tr1ng_m3_up_b3f0r3_y0u_g0_go}`

### Escape Plane

[Aperi'Solve](https://aperisolve.fr/) 

<img src="https://user-images.githubusercontent.com/26357716/160218330-ccb0ca4c-7f8f-4b27-bfb5-aeaa5c5dbe51.png" width="200"/>

<img src="https://user-images.githubusercontent.com/26357716/160218328-f75ff767-245f-454f-addb-4676ac08f4f1.png" width="200"/>

Scanning the QR codes gives us `WH2022{rGb_h1d3s_1nf0_t00}`

### Garbage Runner
[treasure.pdf](https://github.com/DanielT000/CTFwriteups/files/8354427/treasure.pdf)
`binwalk --dd='.*' treasure.pdf` 

In `_treasure.pdf.extracted`:

<img src="https://user-images.githubusercontent.com/26357716/160218432-70d02428-f557-48d0-8f78-6e413d61ea97.jpg" width="200"/>

`WH2022{m0r3_th4n_m33t5_th3_3y3}`

## Forensics
[Volatility](https://www.volatilityfoundation.org/26)

### The Prompt Within
> The aliens that invaded Earth have gotten a hold of the Whitehacks console and are attempting to communicate back to base! Thankfully, we caught them red-handed... Can you figure out what they have sent back to the Mothership? 

We are given a memdump.mem file.

`volatility_2.6_win64_standalone.exe -f memdump.mem imageinfo` --> `Win7SP1x64` profile

`volatility_2.6_win64_standalone.exe -f memdump.mem --profile=Win7SP1x64 cmdscan` gives us 

```

Cmd #0 @ 0x3df6c0: V0gyMDIye3czX2g1djNfN2gzMXJfYzBuczBsM19yM3F1M3M3MW5nX2I1Y2t1cH0
Cmd #15 @ 0x380158: =                                                                                                   
Cmd #16 @ 0x380158: =
```
Decode base64 of `V0gyMDIye3czX2g1djNfN2gzMXJfYzBuczBsM19yM3F1M3M3MW5nX2I1Y2t1cH0` --> `WH2022{w3_h5v3_7h31r_c0ns0l3_r3qu3s71ng_b5ckup}`
### Jack's Rival

> We know the infamous murderer Jack the Ripper from the 1880s, but are you aware that Jack had a twin brother, John, who also turned out to be his fiercest rival as they compete for fame?

> John was last seen competing to see who could outsing Freddie Mercury in a soprano contest out in the public before he went hiding. He left a file containing a note about his darkest secret. Are you able to retrieve it?

[treasures.zip](https://github.com/DanielT000/CTFwriteups/files/8354471/treasures.zip) is password protected.
We will use zip2john and John the Ripper to crack the password. Note that rockyou.txt is used as the wordlist

`zip2john treasures.zip zip.hash`

`john zip.hash --wordlist=rockyou.txt`

```
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
myroomisblue     (file.zip/John's Top Secret Files/flag.txt)     
1g 0:00:00:00 DONE (2022-03-25 21:19) 5.555g/s 8123Kp/s 8123Kc/s 8123KC/s najm86..mypassis
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Using `myroomisblue` as the password, we can get `flag.txt`: `WH2022{W3_wi11_w3_w1ll_r0cky0u}`


### Do the Shimmy!

> We need you to quickly identify how much they have seen, we have the following piece of intel: An application was executed at: "2022-02-26 18:43:31 UTC+0000"

> Find the application, and we will be able to handle the rest! 

`volatility_2.6_win64_standalone.exe -f memdump.mem --profile=Win7SP1x64 timeliner > timeline.txt` to get a list of all timeline events.

[timeline.txt](https://github.com/DanielT000/CTFwriteups/files/8354436/timeline.txt)

`grep "2022-02-26 18:43:31 UTC+0000" timeline.txt` gives

`2022-02-26 18:43:31 UTC+0000|[SHIMCACHE]| \??\C:\Program Files\Google\Chrome\Application\chrome.exe| `

`WH2022{C:\Program Files\Google\Chrome\Application\chrome.exe}`

## Reverse Engineering

### the floor is java
[the-floor-is-java.zip](https://github.com/DanielT000/CTFwriteups/files/8354474/the-floor-is-java.zip)

We are given a .class file and the encoded message.txt

Using a [Java decompiler online](http://www.javadecompilers.com/) we decompile the .class file to get

[decompileroutput.txt](https://github.com/DanielT000/CTFwriteups/files/8354480/decompileroutput.txt)

In particular, we have 4 functions: `encode1`, `encode2`, `encode3`, `encode4` and the encoded message is `msg = encode3(encode4(encode1(encode2(FLAG))))`

Brief description of each encode:
- `encode1`: takes the characters in even positions of the string, then concatenates with characters in odd positions (0-indexed)
- `encode2`: shifts each character by some amount in `arr`
- `encode3`: takes the last half of the string and concatenates with first half
- `encode4`: reverses the string

We use python to write `decode1`, `decode2`, `decode3` (which is the same as `encode3`), `decode4` and the flag is `decode2(decode1(decode4(decode3(msg))))` 

```python
msg = ",hj*Y/bOi-(Tm0\"0qH,O[d2!'@qG-(-6"

def decode3(x):
    l = len(x)
    return x[l//2:] + x[:l//2]

def decode4(x):
    return x[::-1]

def decode1(x):
    l = len(x)
    p = x[:l//2]
    q = x[l//2:]
    s = "".join([a+b for a,b in zip(p,q)])
    return s

def decode2(X):
    arr = [ 39, 18, 16, 3, 2, 10, 14, 4, 11, 37, 8, 5, 6, 31, 9, 12 ];
    p = [chr(ord(x)+y) for x,y in zip(X, arr+arr)]
    return "".join(p)

flag = decode2(decode1(decode4(decode3(msg))))
print(flag)
```

`WH2022{1_l0v3_r3v3r51ng_5tr1ng5}`



## Cryptography

### Really S1mp(l3) Algorithm

```
This is really simple. I hope you can solve it.

p = 89677525768054651799811339393073439598902155753884683756875620558829954902529

q = 84438062750417241222463359000671279258755386034358736244893269480285225711041

e = 65537

ct = 2006481391032768131106572837821981606814991526844317992631122301790966354846642917808142106585149537517169168108747108233658443914026685951141453359021205
```

This is [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)).

```python
from Crypto.Util.number import *
p = 89677525768054651799811339393073439598902155753884683756875620558829954902529
q = 84438062750417241222463359000671279258755386034358736244893269480285225711041
e = 65537
ct = 2006481391032768131106572837821981606814991526844317992631122301790966354846642917808142106585149537517169168108747108233658443914026685951141453359021205
n = p*q
phi = (p-1)*(q-1)
d = inverse(e,phi)
m = pow(ct,d,n)
print(long_to_bytes(m))
```

`WH2022{1t5_r34lly_s1mpl3_4m_1_r1ght}`



### The Indecipherable Cipher

> Some say this cipher cannot be deciphered. Well, do you believe them?
>
> Even worse, some say this cipher is misattributed!
>
> I would say that the key to solving this challenge is to remember who the true inventor was.

We are given `CP2022{j1b3n3e3_15_Pcn_Xa3f@x_K1dC3R_0A_yB3F01Ys}`.

From some analysis of the numbers in `j1b3n3e3` (what I did), or googling "The Indecipherable Cipher" we can guess that it is the [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)

For the key, the challenge description mentions the "true inventor" which is Giovan Battista Bellaso.

Using "giovan" as our key, we decode the Vigenère cipher [online](https://gchq.github.io/CyberChef/#recipe=Vigen%C3%A8re_Decode('giovan')&input=Q1AyMDIye2oxYjNuM2UzXzE1X1Bjbl9YYTNmQHhfSzFkQzNSXzBBX3lCM0YwMVlzfQ) to get `WH2022{v1g3n3r3_15_Juz_Ca3s@r_C1pH3R_0N_sT3R01Ds}`

### The Poem of Knowledge

> Our knowledgeable alien friend named Beale left us with a purported "Poem of Knowledge" before he went back to his universe.
>
> He also dropped a message behind. Can you decipher what he was trying to say?
> 
> 17-73-24-55-84-101-141-44-54-49-10-123-62-131-114-67-47-46-60-83-84 
[Poem Of Knowledge.txt](https://github.com/DanielT000/CTFwriteups/files/8354538/Poem.Of.Knowledge.txt)

Apparently this was the [Beale ciphers](https://en.wikipedia.org/wiki/Beale_ciphers) (I did not realise this) and you just take the first letter of the i-th word for each i (which I guessed).

```python
poem = """
The Road Not Taken
By Robert Frost

Two roads diverged in a yellow wood,
And sorry I could not travel both
And be one traveler, long I stood
And looked down one as far as I could
To where it bent in the undergrowth;

Then took the other, as just as fair,
And having perhaps the better claim,
Because it was grassy and wanted wear;
Though as for that the passing there
Had worn them really about the same,

And both that morning equally lay
In leaves no step had trodden black.
Oh, I kept the first for another day!
Yet knowing how way leads on to way,
I doubted if I should ever come back.

I shall be telling this with a sigh
Somewhere ages and ages hence:
Two roads diverged in a wood, and I—
I took the one less traveled by,
And that has made all the difference."""

import re
regex = re.compile('[^a-zA-Z]+')
a = regex.sub(" ", poem)
b = a.split(" ")
pos = [17, 73, 24, 55, 84, 101, 141, 44, 54, 49, 10, 123, 62, 131, 114, 67, 47, 46, 60, 83, 84]

print("".join([b[x][0] for x in pos])) # the indexing settles itself

```

`WH2022{IHopeYouhadagreattime}`
### Ridiculously Simpler Algorithm

```
This is supposedly even simpler. Try me!

n = 10737815683051749791647908968171036410193052055925978453198599402338822997173859289423308183048750681303695147135467822832842221572174477705930888427996441

e = 65537

c = 2025103500488147486354827835413388045219955669590787897403050967001645770151549545526845887271487454606326620556228871888382889102118986522714812376848980
```

This is RSA again.

Factoring n using [Alpertron](https://www.alpertron.com.ar/ECM.HTM) or [FactorDB](http://factordb.com/index.php?query=10737815683051749791647908968171036410193052055925978453198599402338822997173859289423308183048750681303695147135467822832842221572174477705930888427996441) gives us

`n = p*p` where `p = 103623432113840688941320755085280743977542506826507607745384835169310947238021`

For the case `p = q` in RSA, `phi = p*(p-1)` instead of the usual `(p-1)*(q-1) = (p-1)^2`

```python
from Crypto.Util.number import *
n = 10737815683051749791647908968171036410193052055925978453198599402338822997173859289423308183048750681303695147135467822832842221572174477705930888427996441
e = 65537
ct = 2025103500488147486354827835413388045219955669590787897403050967001645770151549545526845887271487454606326620556228871888382889102118986522714812376848980
p = 103623432113840688941320755085280743977542506826507607745384835169310947238021
phi = (p-1)*p
d = inverse(e,phi)
m = pow(ct,d,n)
print(m)
print(long_to_bytes(m))
```

gives us 

```
87725048505012310448119951005211451951214811795991145299107951095195116119499951125
b'\x0b\x8fhN.>`k\xe5-\xed\xfb\xac\x91\xfa\xf4\xf1\xdd\xe8X\xd5\xc5\x0f\xf7\x01\x06H\xa4\x9d\x19\xd6V;L\x15'
```

Seems like garbage, but lets look at `m`.

You can manually split the string `m` to get a bunch of ascii decimal values, and decode using [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Decimal('Space',false)&input=ODcgNzIgNTAgNDggNTAgNTAgMTIzIDEwNCA0OCAxMTkgOTUgMTAwIDUyIDExNCA1MSA5NSAxMjEgNDggMTE3IDk1IDk5IDExNCA1MiA5OSAxMDcgOTUgMTA5IDUxIDk1IDExNiAxMTkgNDkgOTkgNTEgMTI1). 

`87 72 50 48 50 50 123 104 48 119 95 100 52 114 51 95 121 48 117 95 99 114 52 99 107 95 109 51 95 116 119 49 99 51 125` --> `WH2022{h0w_d4r3_y0u_cr4ck_m3_tw1c3}`
