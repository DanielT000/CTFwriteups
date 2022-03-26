## (CSA) Foil the Plot

> Missing challenge description, but its some plot about information hidden behind a log in screen. 
> 
> The page authenticates passwords by:
>    - Splitting the 40-character password into 2 segments.
>    - Checking if the SHA256 hashes of both segments match in their last 5 bytes.
>
>  After that, we are supposed to get an ID and a postal code for a location.

We need to find a hash collision in the last 5 bytes of SHA256 hashes. This is `5*8 = 40` bits, but by the birthday problem we should be able to get a collision in `sqrt(2^40) = 2^20 ~= 1000000` such hashes.

We store the last 5 bytes of every hash we have found in a dictionary, and whenever we generate a new hash, we check if the last 5 bytes is a key in the dictionary. If so, we have found a collision and thus we have the password.

```python
import hashlib
import random
chars = "0123456789abcdefghijklmnopqrstuvwxyz"

def sha256(x):
    return hashlib.sha256(x).digest()
    
def getcollision():
    d = dict()
    for i in range(2000000):
        if (i % 100000 == 0):       # just to keep track
            print(i) 
        s = "".join(random.choices(chars,k=20))
        s = s.encode()

        p = sha256(s)[-5:]          # last 5 bytes of hash

        if (p in d):
            print(p, d[p], s, sha256(s), sha256(d[p]))
            return d[p], s
            
        d[p] = s

p1, p2 = getcollision()
password = p1 + p2
print(password)
```

Using the password `q2gdp1xq1hrqnjhi04zrpg94dq7kwb5by5gynpoz`, we successfully pass the login.

![image](https://user-images.githubusercontent.com/26357716/160227672-aaa82e69-810d-47fa-a2c3-09b10526b3e7.png)

We receive a message.

Upon exploring further, if you hover your cursor below the image, the following text appears.

`UExBSU5URVhUIDw9PT4gKEFFUy1DQkMsIFNIQS0yNTYoMXN0IHNlZ21lbnQpLCBTSEEtMjU2KDJuZCBzZWdtZW50KSkgPD09PiBDSVBIRVJURVhU` 

Base64 decoded: `PLAINTEXT <==> (AES-CBC, SHA-256(1st segment), SHA-256(2nd segment)) <==> CIPHERTEXT`

This means that we are supposed to use the SHA256 hashes of the 1st and 2nd segments as the key and nonce respectively to AES decrypt the message.

After doing so with a simple script:

```python
import hashlib
from Crypto.Cipher import AES
import base64

def sha256(x):
    return hashlib.sha256(x).digest()
p1 = b"q2gdp1xq1hrqnjhi04zr"
p2 = b"pg94dq7kwb5by5gynpoz"
key = sha256(p1)
iv = sha256(p2)
ct = "xXJmIS3Tk+uIf5L/g801edMzwC4UFYZj1UYbaRXsm7tmJNsupUZzLPL/r4wlPacnBkf7ics0F9tjbYxEnophYGBF/7Yts83665OIAZwnM2o3KsTzvQKUgXnexvS8TWEGiAjPd+As/bCTzl/mx87YNw=="
s = base64.b64decode(ct)
cipher = AES.new(key, mode=AES.MODE_CBC, iv=iv[:16])  
msg = cipher.decrypt(s)
print(msg)
```

we get `[ID: h@$h_c011i$i0n] It is a tiger. It is also a leopard. It is the route to a chilling glimpse of hell.`.

This means our ID is `h@$h_c011i$i0n`, and to find the location we can just google `It is a tiger. It is also a leopard. It is the route to a chilling glimpse of hell.` which gives us Haw Par Villa. The postal code is `118628`. 

Flag: `WH2022{h@$h_c011i$i0n_118618}`
