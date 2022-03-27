## Booleancrypt

Source:
```python
#!/usr/bin/python3
import os
import random
import base64

Not = lambda x: 255-x

Or = lambda x,y:x|y
And = lambda x,y:x&y
xor = lambda x,y:x^y
nor = lambda x,y:Not(x|y)
nand= lambda x,y:Not(x&y)
xnor = lambda x,y:Not(x^y)
xand = lambda x,y:Not(x&y)&(x&y)  # Exclusive AND...? Returns true if x and y are true, except when they are, then retrun false...?
xnand = lambda x,y:Not(x&y)|(x&y)  # Exclusive NAND...? Return true if x and y are not true, except when they are, then return true...?

def encrypt(data, key, func):
    length = len(key)
    output = []
    for i in range(len(data)):
        output.append(func(data[i],key[i%length]))
    print(output)
    return bytes(output)

if __name__ == "__main__":
    file_path = 'flag'
    with open(file_path, 'rb') as file:
        data = file.read()

    key = []
    for i in range(random.randrange(8192, 16384)):
        key.append(random.randrange(0,255))
    key = bytes(key)

    rand = random.randrange(0, 8)
    function = [Or, And, xor, nor, nand, xnor, xand, xnand]

    print (base64.b64encode(encrypt(data, key, function[rand])).decode("utf-8"))
```

In short, the server applies a random bitwise function with a random bytestring to the flag, and sends it to us.

We can aim to leak the bits of the flag by doing statistical analysis.

Let us investigate the truth tables for each function.

| X | Y | OR | AND | XOR | NOR | NAND | XNOR | XAND | XNAND |
| - | - | - | - | - | - | - | - | - | - |
| 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 0 | 1 |
| 0 | 1 | 1 | 0 | 1 | 0 | 1 | 0 | 0 | 1 |
| 1 | 0 | 1 | 0 | 1 | 0 | 1 | 0 | 0 | 1 |
| 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 |

We can approximate the data to be a random binary string, where each bit has equal probability of being 0 or 1.

As such, we can guess what function was applied to the flag given the proportion of 1s in the result string, as all outcomes in the truth table will be equally likely.

- XAND: 0%
- AND: 25%
- NOR: 25%
- XOR: 50%
- XNOR: 50%
- NAND: 75%
- OR: 75%
- XNAND: 100%

We can see that XAND and XNAND are basically useless.

Upon closer inspection, XOR and XNOR are also useless since their result strings have 50% of bits as 1s, and since each bit is independent we cannot distinguish between XOR and XNOR, and even between XOR and a random bitstring. 



