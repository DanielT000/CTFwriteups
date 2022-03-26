# Meet where? Middle Road?

> My lecturer told me that DES is not secure and I should use AES for encryption.
>
> Here's what I have as part of my school project to securely encrypt messages on where to meet my friends. I am sure no one can crack AES encryption. 

Source: 
```python
from random import randint
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

AES_KEY_SIZE = 16

flag = b"WH2022{fake_flag_for_testing}"

# Some say 0 is not a good number.
def get_new_key() -> bytes:
    digits = b"123456789"
    fav_event = b"wH1t3H@cK5_"

    while len(fav_event) < AES_KEY_SIZE:
        fav_event += bytes([digits[randint(0, 8)]])

    return fav_event


# Encrypting twice will make AES even stronger!
def encrypt(data, key1, key2):
    cipher1 = AES.new(key1, mode=AES.MODE_ECB)
    ct = cipher1.encrypt(pad(data, AES.block_size))
    cipher2 = AES.new(key2, mode=AES.MODE_ECB)
    ct = cipher2.encrypt(ct)

    ct = b64encode(ct).decode("utf-8")

    return ct


def solve_me():
    key1 = get_new_key()
    key2 = get_new_key()

    ct = encrypt(flag, key1, key2)

    print(
        "Welcome to my personal encryption project\n"
        + "Where to meet next:\n"
        + ct
        + "\n\nTest out this secure encryption scheme:\n> ",
        end="",
    )

    try:
        pt = input().strip()
        custom_enc = encrypt(pt.encode("utf-8"), key1, key2)
        print(custom_enc + "\n")
        exit(1)
    except Exception as e:
        print(e)
        print("Error!\n")
        exit(1)


if __name__ == "__main__":
    solve_me()
```

The program generates 2 random keys of the form `wH1t3H@cK5_#####` where `#####` consists of the digits `1-9` inclusive. (e.g `wH1t3H@cK5_31337`)
This gives us `9^5 = 59049` possible keys.

The program then encrypts the flag with two instances of [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) using each key.

We are allowed to encrypt 1 message of our own to obtain both the plaintext and the ciphertext. This is vulnerable to the [known-plaintext attack](https://en.wikipedia.org/wiki/Known-plaintext_attack) since the keys are reused.

Let us send a message `m` to the server and receive the output `c`.

We can try every combination `(key1, key2)` to see if `encrypt(m, key1, key2) == c`. If so, we have found `key1` and `key2`, and can use that to decrypt the flag.

However, there are `59049*59049 = 3486784401` possible combinations, which is too many and will not run in time.

The solution is to make use of the [meet-in-the-middle](https://en.wikipedia.org/wiki/Meet-in-the-middle_attack) attack. 

Lets have the following helper functions.

```python
def enc(data, key):                                  # encrypt once
    cipher = AES.new(key, mode=AES.MODE_ECB)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return ct

def dec(data, key):                                  # decrypt once
    cipher = AES.new(key, mode=AES.MODE_ECB)
    m = cipher.decrypt(data)
    return m

```

We encrypt our message `m` using all 59049 possible keys `key1`, and store them in a dictionary D as using `enc(m, key)` as the key and `key` for the value. 

Now for all possible `enc(m, key1)`, we know the `key1` used to encrypt it.

We then decrypt our output `c` using all 59049 possible keys `key2`. For each `dec(c, key2)` we check if it exists in D.

If so, we have `enc(m, key1) == dec(c, key2)` --> `enc(enc(m, key1), key2) == enc(dec(c, key2), key2) == c`.
Thus, we have found `key1` and `key2` used for the original message.

We can then decrypt the encrypted flag we got earlier using the keys.

This runs fast enough. The previous method was `O(n^2)`, but our method runs in amortised `O(n)` due to dictionary lookup being fast.

Full solve script:

```python
import telnetlib 
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def enc(data, key):                                  # encrypt once
    cipher = AES.new(key, mode=AES.MODE_ECB)
    ct = cipher.encrypt(pad(data, AES.block_size))
    return ct

def dec(data, key):                                  # decrypt once
    cipher = AES.new(key, mode=AES.MODE_ECB)
    m = cipher.decrypt(data)
    return m

tn = telnetlib.Telnet("challenges1.whitehacks.xyz", 41337)   # yes, i use telnet
tn.read_until(b"Where to meet next:\n")

encrypted_flag = base64.b64decode(tn.read_until(b"\n")[:-1]) # the encrypted flag, base64 decoded

tn.read_until(b"Test out this secure encryption scheme:\n")

m = b"a"            # the plaintext we send

tn.write(m + b"\n") # send message m to the server

tn.read_until(b"> ")

c = base64.b64decode(tn.read_until(b"\n")[:-1]) # receive ciphertext c from server, decode base64

# Generate all possible keys
keys = []
for i in range(10000, 100000):
    if ("0" in str(i)): continue       
    keys.append(b"wH1t3H@cK5_"+str(i).encode())  

D = dict()

for key1 in keys:
    D[enc(m, key1)] = key1   # store all possible enc(m, key1) in D.

for key2 in keys:
    mid = dec(c, key2)       # the "middle" step.
    if (mid in D):
        key1 = D[mid]        # obtain key1 used so that enc(m, key1) = mid
        print("Keys used: ", key1, key2)
        print(dec(dec(encrypted_flag, key2), key1))
```

Flag: `WH2022{M1dDl3_R0@d_15_tH3_b3sT_pLAc3_2_m33T}`
