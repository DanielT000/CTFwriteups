## Hypersphere

> Why would anyone use quaternion to do DLP...

main.py (edited for some brevity)
```python
from secrets import randbits
from hashlib import shake_256
from Crypto.Util.number import isPrime
import point

FLAG = <REDACTED>

p = 7489556970112255858194339343279932810383717284810081135153576286807813194468553481550905061983955290055856497097494238457954616159153509677256329469498187
ga = 2258050144523952547356167241343623076013743172411353499204671793264857719189919436799943033376317821578765115886815403845812363461384417662956951961353685
gb = 1069914179693951322883111467335954654818815798644770440034358650042824371401982086159904675631799159962201142170062814585463048527613494928890992373946863
gc = 11133097852046797355391346851525395533946845181651405581054631571635854160968086
gd = 7489556970112255858194339343279932810383717284810081135153576286807813194460592232877165912462810721221949401180338198644010019265640599992748426319034311

h = 512

g = point.Point(ga, gb, gc, gd, p)

def encrypt(msg : bytes, key : str) -> str:
    otp = shake_256(key.encode()).digest(len(msg))
    return xor(otp, msg).hex()

def xor(a : bytes, b : bytes) -> bytes:
    return bytes([ x ^ y for x, y in zip(a, b)])

def checkPrime(prime : int) -> bool:
    return prime.bit_length() >= 512 and isPrime(prime)

def checkPoint(ta : int, tb : int, tc : int, td : int) -> bool:
    cond1 = 10 < ta < p - 2
    cond2 = 10 < tb < p - 2
    cond3 = 10 < tc < p - 2
    cond4 = 10 < td < p - 2
    cond5 = (ta * ta + tb * tb + tc * tc + td * td) % p == 1
    return cond1 and cond2 and cond3 and cond4 and cond5

def change():
    global p
    global g
    userIn = input("Do you wish to change the prime number and point? Y/N\n")
    if (userIn == "Y"):
        userPrime = int(input("New Prime: "))
        if (not checkPrime(userPrime)):
            print("Your prime is not suitable!")
            exit(0)
        p = userPrime

        userPoint = input("New Point (split by space): ").split()
        ta = int(userPoint[0])
        tb = int(userPoint[1])
        tc = int(userPoint[2])
        td = int(userPoint[3])
        if (not checkPoint(ta, tb, tc, td)):
            print("Your point is not suitable!")
            exit(0)
        g = point.Point(ta, tb, tc, td, p)
    

if __name__ == '__main__':
    print(f"Prime : {p}")
    print(f"Point : {g}")
    change()
    a = randbits(h); b = randbits(h)
    A = g ** a; B = g ** b
    S = A ** b
    key = str(S)
    print(key)
    msg = str(randbits(h)).encode()

    print(f"p = {p}"); print(f"g = ({g})"); print(f"A = ({A})"); print(f"B = ({B})"); 
    print(S)
    print(f"c = {encrypt(msg, key)}\n")

    ans = input("What's the msg?\n")
    if (ans.encode() == msg):
        print("Congratulations! Here's your flag (๑˃ᴗ˂)ﻭ")
        print(FLAG)
    else:
        print("You got it wrong... (＞ｍ＜) Try again!") 
```

point.py:
```python
# Quaternion

class Point():
    def __init__(self, a, b, c, d, p):
        assert (a * a + b * b + c * c + d * d) % p == 1
        self.a = a
        self.b = b
        self.c = c
        self.d = d
        self.p = p

    def __str__(self):
        return f'{self.a}, {self.b}, {self.c}, {self.d}'

    def __mul__(self, other):
        assert self.p == other.p
        na = (self.a * other.a - self.b * other.b - self.c * other.c - self.d * other.d) % self.p
        nb = (self.a * other.b + self.b * other.a + self.c * other.d - self.d * other.c) % self.p
        nc = (self.a * other.c - self.b * other.d + self.c * other.a + self.d * other.b) % self.p
        nd = (self.a * other.d + self.b * other.c - self.c * other.b + self.d * other.a) % self.p
        return Point(na, nb, nc, nd, self.p)

    def __pow__(self, a):
        res = Point(1, 0, 0, 0, self.p)
        g = Point(self.a, self.b, self.c, self.d, self.p)
        while (a > 0):
            if (a & 1): res = res * g
            g = g * g
            a //= 2
        return res
```

In short, we are given a custom Diffie-Hellman encryption scheme where quartenions are used modulo some prime $p$. In particular, the quartenions are vectors $(a, b, c, d)$ such that $(a^2 + b^2 + c^2 + d^2) = 1 \mod p$. The group operations are implemented in `point.py`.

Note that the identity element of this group, denoted by $1$ is $(1,0,0,0)$.

The [Diffie-Hellman key exchange](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) involves two parties Alice and Bob who want to compute a shared secret between them. It follows a few steps.
1. The generator $g$ is agreed by Alice and Bob
2. Alice selects her private key $a$ and sends $A = g^a$ to Bob.
3. Bob selects his private key $b$ and sends $B = g^b$ to Alice.
4. Both Alice and Bob compute the shared secret $S = g^{ab} = A^b = B^a$.

The security of Diffie-Hellman comes from the fact that usually, computing $a$ from $g$ and $A = g^a$ and similarly for $b$ under some group is difficult. This is known as the discrete logarithm problem.

The challenge shows us an instance of this key exchange and asks us to recover the message encrypted (with another encryption function) using the shared key that was generated.

However, in this challenge, we are given the option to change the prime number $p$ used as well as the generator point $g$, subject to some constraints. This is very suspicious.



### Small subgroup confinement attack

Usually, for these kind of challenges, the order of the generator (the minimum $x$ such that $g^x = 1$) is around $p$, usually $p-1$. We can confirm this with a simple check:
```python
>>> print(g ** (p-1))
1, 0, 0, 0
```

Now that we know the order of the generator, we can factorise it in [Alpertron](https://www.alpertron.com.ar/ECM.HTM) and see that it has small factors like 2 and 3\*3. This allows us to effectively choose a generator with a small order. With a small order, the possible values of $g^x$ will be limited, and thus $x$ can usually be found.

However, we also cannot just send $(1,0,0,0)$ as our generator (even though it has an order of 1) since there are checks in place. Thus, we need to find a good generator, and we observe that $g' = g^{\frac{p-1}{9}}$ is good. This has an order of 3. 
(Note: usually, to find a subgroup with order $x$ in a group with order $k$, we can usually do $g^{\frac{k}{x}}$ to get it. This is used in the Pohlig-Hellman algorithm for solving certain discrete logarithm problems.)

Thus, we can change $g$ to $g'$, and if either $a$ or $b$ generated is a multiple of 3, then we will have $S = g'^{ab} = 1$. This gives us about a 5/9 chance of getting the flag with each interaction.

For each interaction, we change the generator to $g'$ (keeping $p$ same), and assume the secret generated is $(1,0,0,0)$. Then we use the secret to decrypt the message sent and pass the check to get the flag. (It is worth noting the the `encrypt` function involves an `xor` and is actually the same as the decryption function.)

Solve script:
```python
from pwn import *
from hashlib import shake_256
from Crypto.Util.number import isPrime
import point

def encrypt(msg : bytes, key : str) -> str: # same as decryption
    otp = shake_256(key.encode()).digest(len(msg))
    return xor(otp, msg).hex()

def xor(a : bytes, b : bytes) -> bytes:
    return bytes([ x ^ y for x, y in zip(a, b)])

p = 7489556970112255858194339343279932810383717284810081135153576286807813194468553481550905061983955290055856497097494238457954616159153509677256329469498187
ga = 2258050144523952547356167241343623076013743172411353499204671793264857719189919436799943033376317821578765115886815403845812363461384417662956951961353685
gb = 1069914179693951322883111467335954654818815798644770440034358650042824371401982086159904675631799159962201142170062814585463048527613494928890992373946863
gc = 11133097852046797355391346851525395533946845181651405581054631571635854160968086
gd = 7489556970112255858194339343279932810383717284810081135153576286807813194460592232877165912462810721221949401180338198644010019265640599992748426319034311

h = 512

g = point.Point(ga, gb, gc, gd, p)

g = g**((p-1)//9)

r = remote("challs.nusgreyhats.org",10521)

r.sendline(b"Y")
r.sendline(str(p).encode())
r.sendline(" ".join(map(str, [g.a, g.b, g.c, g.d])).encode())

r.recvuntil(b"c = ")
c = r.readline(keepends=False).decode()

key = "1, 0, 0, 0"
r.sendline(bytes.fromhex(encrypt(bytes.fromhex(c), key)))
r.interactive()
```
Flag: `grey{HyperSphereCanBeUsedForKeyExchangeToo!(JustProbablyNotThatSecure)_33JxCZjzQQ7dVGvT}`
