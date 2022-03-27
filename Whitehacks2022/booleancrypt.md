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


We will choose to look at 25% bitstrings which are either AND or NOR.

How do we distinguish between them?

| X | Y | AND | NOR |
| - | - | - | - | 
| 0 | 0 | 0 | 1 | 
| 0 | 1 | 0 | 0 |
| 1 | 0 | 0 | 0 | 
| 1 | 1 | 1 | 0 | 

Notice that for AND results, 1 occurs if the corresponding bit in X is 1.

For NOR results, 1 occurs only if the corresponding bit in X is 0.

Thus AND and NOR results will never have common 1 bits.

From this, we can filter out either NOR or AND results only. We store a string `ans` which represents the bits of X we have recovered.

For each result string `res` that has ~25% 1s, we check if `ans` and `res` share any common bits. (This is done with an AND operation).

If they do, we OR `res` and `ans` to uncover more 1s in X.

Note that we still do not know if the results we are using all are from AND queries or all from NOR queries.

However, notice that `X NOR random_bit_string = NOT(X) AND NOT(random_bit_string) = NOT(X) AND effectively_another_random_bit_string`, hence if we used all NOR queries we just need to flip all the bits in `ans`. We can just write both `ans` and `NOT(ans)` to files.

------------------------------------------------------------------------------------------------------------------------------------------------------

Unfortunately for this writeup, I accidentally overwrote the actual file while tidying up my solve script and the challenge server was no longer up.

Below is a prototype using a `.png` file from another challenge, which has a larger size and thus requires more queries. 

![SMU_hidden](https://user-images.githubusercontent.com/26357716/160264411-606cad12-03b6-4a22-a7df-cdf2801fd32f.png)

During the actual CTF, I used only around 100 queries to the server. 

I also had to look for the file signatures in the output files to determine that it was indeed a `.png` file.

```python
#!/usr/bin/python3
import os
import random
import base64
import telnetlib

Not = lambda x: 255-x

Or = lambda x,y:x|y
And = lambda x,y:x&y
xor = lambda x,y:x^y
nor = lambda x,y:Not(x|y)
nand= lambda x,y:Not(x&y)
xnor = lambda x,y:Not(x^y)
xand = lambda x,y:Not(x&y)&(x&y)  
xnand = lambda x,y:Not(x&y)|(x&y)

file_path = 'SMU_hidden.png'        # random file for testing
with open(file_path, 'rb') as file:
    data = file.read()

def encrypt(data, key, func):
    length = len(key)
    output = []
    for i in range(len(data)):
        output.append(func(data[i],key[i%length]))
    return output

def hmm():
    key = []
    for i in range(random.randrange(8192, 16384)):
        key.append(random.randrange(0,255))
    key = bytes(key)

    rand = random.randrange(0, 8)
    function = [Or, And, xor, nor, nand, xnor, xand, xnand]
    return encrypt(data, key, function[rand])

# Helper functions.

def AND(x, y):
    return bytes([a&b for a,b in zip(x,y)]);

def OR(x, y):
    return bytes([a|b for a,b in zip(x,y)]);

def NOT(x):
    return bytes([255^a for a in x]);

def cnt(y):
    x = int.from_bytes(y, byteorder='big')
    return bin(x).count("1")

# Thresholds for number of 1s.

lo = int(0.20*len(data)*8)
hi = int(0.30*len(data)*8)

ans = -1                # sentinel value
for i in range(500):

    # What I used to query the server, which is not up now.
    #tn = telnetlib.Telnet("challenges1.whitehacks.xyz",43232)   
    #res = tn.read_until(b"\n")[:-1]
    #res = eval(a)
     
    res = hmm()      # Tester function I repurposed from original code.

    res = bytes(res) # Convert to bytes
    c = cnt(res)     # Count 1s
    
    if (c > lo and c < hi):
        if (ans == -1):                   # If this is the first such string we have
            ans = res;
        else:
            if (cnt(AND(ans, res)) != 0):  # If `res` is of the same type as `ans` (either AND or NOR).
                ans = OR(ans, res)
                

# Use both possible versions

with open("file1.png", "wb") as f:
    f.write(ans)

with open("file2.png", "wb") as f:
    f.write(NOT(ans))
    
assert(ans == data or NOT(ans) == data)   # just to validate the prototype
```

Flag: `WH2022{XNAND_THE_ONE_TRUE_BOOLEAN}` or something like that, I don't have it now.
