# MysteryCrypt

### Description:
> We found this encryption algorithm being used after the key exchange. We suspect that it is very weak and can be cracked in a short amount of time. 

### Source:
```py
import random
import os
import signal

key = random.randint(2, 2**32-1)
delta = 0x9E37 ^ 0x79B9
FLAG = os.getenv('FLAG')

def mod(x):
    return x % (2**16)

k1 = mod(key >> 16)
k2 = mod(key)
def ror(n, k):
    return (n << k) | (n >> (16 - k))
def rol(n, k):
    return (n >> k) | (n << (16 - k))
def round(l, r, k1, k2):
    res = mod((ror(r,4) ^ rol(r,5) ^ k1) + r) ^ mod(k2 + r + delta)
    return (r, l ^ res)

def encrypt(num):
    l, r = mod(num >> 16), mod(num)
    for i in range(128):
        l, r = round(l, r, k1, k2)
    return (l << 16) + r

signal.alarm(120)
for i in range(100000):
    print("1 = encrypt, 2 = submit key")
    choice = int(input())
    if choice == 1:
        print("input 32 bit integer: ")
        num = int(input())
        print(f"encrypted = {encrypt(num)}")
    elif choice == 2:
        print("key = ?")
        inputkey = int(input())
        if inputkey == key:
            print(open(FLAG).read())
        else:
            print('Wrong!')
        break

```

### Initial analysis

Looking at the source, we have an `encrypt` function, which seems to apply `round` to our input 128 times, using two keys `k1` and `k2`. 

We are allowed to query for the encryption of any 32-bit integer, up to 100000 queries. 
If we manage to guess `key = (k1<<16) + k2` correctly, we will get the flag. 

The 32-bit integer input we provide is split into two halves `l` and `r` (the upper and lower 16-bits respectively) in the `encrypt` function. 


Looking at the `round` function (which we will call `F` from now onwards for brevity):
```py
def round(l, r, k1, k2):
    res = mod((ror(r,4) ^ rol(r,5) ^ k1) + r) ^ mod(k2 + r + delta)
    return (r, l ^ res)
```
The function derives some number `res` from `r`, `k1` and `k2` and XORs it with `l` to give a new number, before swapping the two when returning.
Briefly, 
$$F(l,r) = (r, l \oplus \text{res})$$ where $\oplus$ denotes the XOR operator. How `res` is derived does not matter too much at this point.


Importantly, with any input `(l,r)` to `F` we know 16 bits of the output, which is `r`. However, since `encrypt` does `F` 128 times, we still do not know anything about the output of `encrypt` given an input.

### Part 1

Let us consider $F(0,0)$. The notation is slightly inaccurate for brevity; technically I am supposed to write $F((0,0))$ instead of $F(0,0)$.

We have $F(0,0) = (0, \text{res})$ from earlier, since $0 \oplus \text{res} = \text{res}$.
This gives us $2^{16} = 65536$ possible values of `res` to try, and we are guaranteed that one of them is the correct output of $F(0,0)$. Let this value of `res` be `x`.

Now that we have $(0,x) = F(0,0)$, let us look at what happens if we encrypt `(0,x)`. Since `encrypt` calls `F` 128 times on our input, we have:

$$
\begin{alignat*}{4}
& \text{encrypt}(0,x) &&= F^{128}(0,x) \\ 
&  &&= F^{128}(F(0,0)) \\ 
&  &&= F^{129}(0,0) \\ 
&  &&= F(F^{128}(0,0)) \\  
&  &&= F(\text{encrypt}(0,0)) 
\end{alignat*}
$$

So, similarly to how $(0, 0)$ and $F(0,0) = (0,x)$ are linked, we now know there is a link between $\text{encrypt}(0,0)$ and $\text{encrypt}(0,x)$, namely that $$\text{encrypt}(0,0)\text{.r} = \text{encrypt}(0,x)\text{.l}$$

This condition gives us a good way to check if our value of `res` guessed is a correct value. While this could also happen out of pure luck, the chance of this happening is $\frac{1}{2^{16}}$, so the number of false positives will be low. 

### Part 2

Now let us look at how `res` is generated. The main line of code in `F` is:
```py
res = mod((ror(r,4) ^ rol(r,5) ^ k1) + r) ^ mod(k2 + r + delta)
```

where `ror` and `rol` are "rotating" kind of functions, and the `mod` functions are meant to keep our values to 16-bit integers. `delta` is a fixed integer.
Note that `ror(0, 4)` and `rol(0,5)` are still `0` (this is the reason why we chose to look at `(0,0)` earlier.
Simplifying further, we have 
```py
res = mod((0 ^ 0 ^ k1) + 0) ^ mod(k2 + 0 + delta)
```
or 
```py
res = k1 ^ mod(k2 + delta)
```
Written another way, we have 
```py
k1 = res ^ mod(k2 + delta)
```


Thus given a value of `res` we are testing, if we try a value of `k2`,  `k1` is basically determined for us (else we will not get the correct value of `res` from `F`).

Given a guess of the keys `k1` and `k2`, we can then check against the encryption of `(0,0)` and see if the output is identical, which will indicate that we have found the correct key. 


Our solution steps are follows:

1. Guess the value of `res` such that $F(0,0) = (0, res)$.
2. To check if our value of `res` is reasonable, we need $\text{encrypt}(0,0)\text{.r} = \text{encrypt}(0,x)\text{.l}$
3. If our value of `res` is reasonable, guess a value of `k2` and get the corresponding value of `k1`. 
4. Using these values `k1` and `k2` as our key, test if $\text{encrypt}(0,0)$(done locally) is the same as what the server tells us.
5. If they are the same, submit `key = (k1<<16) + k2` to the server to get our flag.

Note that we can just query all values of `encrypt(0,x)` from the server before proceeding with our solution.
This reduces the back-and-forth interaction with the server, saving us time.

In total, this takes us exactly 65536 queries to the server, which is under the limit of 100000. The total number of possible keys `(k1, k2)` we check is also a small multiple of 65536, which will run in time. 

### Solve script:
```py
from pwn import *

delta = 0x9E37 ^ 0x79B9

def mod(x):
	return x % (2**16)
	
def ror(n, k):
	return (n << k) | (n >> (16 - k))
def rol(n, k):
	return (n >> k) | (n << (16 - k))
def round(l, r, k1, k2):
	res = mod((ror(r,4) ^ rol(r,5) ^ k1) + r) ^ mod(k2 + r + delta)
	return (r, l ^ res)

# rewrite the function to allow for trying of our own keys
def encrypt(num, key):
	k1 = mod(key >> 16)
	k2 = mod(key)
	l, r = mod(num >> 16), mod(num)
	for i in range(128):
		l, r = round(l, r, k1, k2)
	return l, r


def SPLIT(x): # splits a 32-bit integer into two 16-bit halves.
	return (x>>16), (x&0xffff)

r = remote("157.245.52.169",32189) # challenge server

tosend = b""
for x in range(65536): # SPLIT(x) = (0,x)
	tosend += b"1\n"+str(x).encode()+b"\n"

# send all our queries at once
r.send(tosend) 

# read our responses one at a time
enc = [0 for i in range(65536)]
for i in range(65536):
	r.readline()
	r.readline()
	enc[i] = int(r.readline().decode().strip().split("=")[-1]) 
	# split the responses into 16-bit halves
	enc[i] = SPLIT(enc[i]) 

for res in range(1, 65536):
	
	# if encrypt(0, res).l = encrypt(0, 0).r
	# res may be correct
	if (enc[res][0] == enc[0][1]): 

		# try all values of k2
		for k2 in range(65536): 

			# k1 is determined
			k1 = mod(k2+delta)^res 

			# derive key
			key = (k1<<16)+k2 

			# test if our locally encrypted matches the server response
			if (encrypt(0, key) == enc[0]):

				# we got the key, submit to server get flag
				print(f"FOUND KEY = {key}")
				r.sendlineafter(b"submit key", b"2")
				r.sendlineafter(b"key = ?\n", str(key).encode())
				r.interactive()
```

### Conclusion

After the CTF, I found out that the encryption is based off a [Feistel cipher](https://en.wikipedia.org/wiki/Feistel_cipher), and that this attack was called a [Slide attack](https://en.wikipedia.org/wiki/Slide_attack). 

What is interesting is that this attack works regardless of the number of rounds used in the Feistel cipher.


