## Probability

> I've been learning about probability distributions, but it's all very confusing so I'm just going to assume that my variant of blackjack gives an advantage to the house. I'll even bet a flag on it.

Source:
```py
import random

def play_round():
    p1 = 0
    while True:
        drawn = random.random()
        p1 += drawn
        print(f'You draw a [{drawn}]. (p1 = {p1})')
        if p1 >= 1:
            print('You have gone bust. Dealer wins!')
            return 1
        if input('Do you want to hit or stand? ').lower() in ['s', 'stand']:
            break
          
    p2 = 0
    while p2 <= p1:
        drawn = random.random()
        p2 += drawn
        print(f'Dealer draws a [{drawn}]. (p2 = {p2})')
    
    if p2 >= 1:
        print('Dealer has gone bust. You win!')
        return 0
    else:
        print(f'Dealer has a higher total. Dealer wins!')
        return 1

def main():
    print('================================================================================')
    print('    Welcome to the SEETF Casino. We will play 1337 rounds of 1337 blackjack.    ')
    print('   You play first, then the dealer. The highest total under 1 wins the round.   ')
    print('  If you win at least 800 rounds, you will be rewarded with a flag. Good luck!  ')
    print('================================================================================')

    scores = [0, 0]
    for i in range(1337):
        print(f'Round {i + 1}:')
        winner = play_round()
        scores[winner] += 1
        print(f'Score: {scores[0]}-{scores[1]}')
        print('-' * 80)
        
        if scores[0] >= 800:
            from secret import flag
            print(f'Here is your flag: {flag}')
            return
            
    print('Better luck next time!')

if __name__ == '__main__':
    main()
```

In this challenge, we play a game of blackjack with the server, where we obtain outputs between 0 and 1 and try to not exceed a sum of 1. The goal is to win 800 out of 1337 games.

### Part 1: Predicting random numbers
Upon inspecting the source, we see that the outputs are obtained via the `random.random()` function.

A quick look at the `random` library gives us this warning:
> Warning: The pseudo-random generators of this module should not be used for security purposes. For security or cryptographic uses, see the secrets module.

The `random` library uses the Mersenne Twister as the generator, which is not cryptographically secure and given 624 known 32-bit outputs, we can predict the rest of the outputs.
Usually, I use [this library by kmyk](https://github.com/kmyk/mersenne-twister-predictor/blob/master/mt19937predictor.py) but this only provides an implementation for the function `getrandbits(32)`, while this challenge uses `random()`. Thankfully, I also found [this library by icemonster](https://github.com/icemonster/symbolic_mersenne_cracker) that allows us to enter in partial outputs from the random generator and it will help us find the best guess. 
All that is left to do is to find out how exactly a random number is generated in the `random()` function.
From kmyk's library and also [the actual code](https://github.com/python/cpython/blob/530f506ac91338b55cf2be71b1cdf50cb077512f/Modules/_randommodule.c) from the `random` library, we find something like this:
```python
def random(self):
        '''The interface for :py:meth:`random.Random.random` in Python's Standard Library
        '''
        a = self.genrand_int32() >> 5
        b = self.genrand_int32() >> 6
        return ((a * 67108864.0 + b) * (1.0 / 9007199254740992.0))
```
Thus, to generate a random number between 0.0 and 1.0, two 32-bit integers are generated first, then truncated and combined to get a 53-bit integer, which is then divided by $2^{53}$ to get a float.

As such, each float we get gives us around 53 bits of information we can feed into the Mersenne cracker, and this is implemented in the `parse_float()` function in the solve script.

### Part 2: Dynamic programming

TODO:

Solve script:
```python
from z3 import *
from random import Random
from itertools import count
import time
import logging
import sys
from pwn import *
sys.setrecursionlimit(4000)

logging.basicConfig(format='STT> %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

SYMBOLIC_COUNTER = count()

class Untwister:
    def __init__(self):
        name = next(SYMBOLIC_COUNTER)
        self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
        self.index = 0
        self.solver = Solver()

    #This particular method was adapted from https://www.schutzwerk.com/en/43/posts/attacking_a_random_number_generator/
    def symbolic_untamper(self, solver, y):
        name = next(SYMBOLIC_COUNTER)

        y1 = BitVec(f'y1_{name}', 32)
        y2 = BitVec(f'y2_{name}' , 32)
        y3 = BitVec(f'y3_{name}', 32)
        y4 = BitVec(f'y4_{name}', 32)

        equations = [
            y2 == y1 ^ (LShR(y1, 11)),
            y3 == y2 ^ ((y2 << 7) & 0x9D2C5680),
            y4 == y3 ^ ((y3 << 15) & 0xEFC60000),
            y == y4 ^ (LShR(y4, 18))
        ]

        solver.add(equations)
        return y1

    def symbolic_twist(self, MT, n=624, upper_mask=0x80000000, lower_mask=0x7FFFFFFF, a=0x9908B0DF, m=397):
        '''
            This method models MT19937 function as a Z3 program
        '''
        MT = [i for i in MT] #Just a shallow copy of the state

        for i in range(n):
            x = (MT[i] & upper_mask) + (MT[(i+1) % n] & lower_mask)
            xA = LShR(x, 1)
            xB = If(x & 1 == 0, xA, xA ^ a) #Possible Z3 optimization here by declaring auxiliary symbolic variables
            MT[i] = MT[(i + m) % n] ^ xB

        return MT

    def get_symbolic(self, guess):
        name = next(SYMBOLIC_COUNTER)
        ERROR = 'Must pass a string like "?1100???1001000??0?100?10??10010" where ? represents an unknown bit'

        assert type(guess) == str, ERROR
        assert all(map(lambda x: x in '01?', guess)), ERROR
        assert len(guess) <= 32, "One 32-bit number at a time please"
        guess = guess.zfill(32)

        self.symbolic_guess = BitVec(f'symbolic_guess_{name}', 32)
        guess = guess[::-1]

        for i, bit in enumerate(guess):
            if bit != '?':
                self.solver.add(Extract(i, i, self.symbolic_guess) == bit)

        return self.symbolic_guess


    def submit(self, guess):
        '''
            You need 624 numbers to completely clone the state.
                You can input less than that though and this will give you the best guess for the state
        '''
        if self.index >= 624:
            name = next(SYMBOLIC_COUNTER)
            next_mt = self.symbolic_twist(self.MT)
            self.MT = [BitVec(f'MT_{i}_{name}', 32) for i in range(624)]
            for i in range(624):
                self.solver.add(self.MT[i] == next_mt[i])
            self.index = 0

        symbolic_guess = self.get_symbolic(guess)
        symbolic_guess = self.symbolic_untamper(self.solver, symbolic_guess)
        self.solver.add(self.MT[self.index] == symbolic_guess)
        self.index += 1

    def get_random(self):
        '''
            This will give you a random.Random() instance with the cloned state.
        '''
        logger.debug('Solving...')
        start = time.time()
        self.solver.check()
        model = self.solver.model()
        end = time.time()
        logger.debug(f'Solved! (in {round(end-start,3)}s)')

        #Compute best guess for state
        state = list(map(lambda x: model[x].as_long(), self.MT))
        result_state = (3, tuple(state+[self.index]), None)
        r = Random()
        r.setstate(result_state)
        return r


def test():
    '''
        This test tries to clone Python random's internal state, given partial output from getrandbits
    '''

    r1 = Random()
    ut = Untwister()
    for _ in range(1337):
        random_num = r1.getrandbits(16)
        #Just send stuff like "?11????0011?0110??01110????01???"
            #Where ? represents unknown bits
        ut.submit(bin(random_num)[2:] + '?'*16)

    r2 = ut.get_random()
    for _ in range(624):
        assert r1.getrandbits(32) == r2.getrandbits(32)

    logger.debug('Test passed!')


# Part 1

def parse_float(random_num):
    random_num = int(random_num*(1<<53))
    x1 = random_num >> 26
    x2 = random_num % (1<<26)
    ut.submit(format(x1,"08b") + '?'*5)
    ut.submit(format(x2,"08b")+ '?'*6)

r = remote("fun.chall.seetf.sg",30001)
ut = Untwister()    
ct = 0
games = 0

while (ct <= 1300):
    cur_total = 0
    r.recvuntil(b"[")
    f = float(r.recvuntil(b"]")[:-1].decode())
    parse_float(f)
    cur_total += f
    ct += 2
    
    while (cur_total < 0.5):
        r.sendline(b"h")
        r.recvuntil(b"[")
        f = float(r.recvuntil(b"]")[:-1].decode())
        parse_float(f)
        cur_total += f
        ct += 2
    
    r.recvline()
    x = r.recvuntil(b" ")[:-1].decode()
    if (x != "You"):
        r.sendline(b"s")
        RES = r.recvuntil(b"Score: ").decode()
        search = re.findall('\[(.*)\]', RES, re.IGNORECASE)
        for x in search:
            parse_float(float(x))
            ct += 2
    else:
    	RES = r.recvuntil(b"Score: ").decode()
    	
    score = r.recvline()[:-1].decode()
    games += 1
    if (games % 20  == 0):
    	print(score)
        
print(ct)
r2 = ut.get_random()

# Part 2

def sim_opp(cur_total, cur):
    opp_total = 0
    opp_cur = cur
    while (opp_total < cur_total):
        opp_total += outputs[opp_cur]
        opp_cur += 1
    if (opp_total > 1):
        return 1, opp_cur
    else:
        return 0, opp_cur

mem = {}

def dp(s, games):
    if (games == 0): return 0
    if ((s, games) in mem):
        return mem[(s, games)]
    cur = s
    cur_total = 0
    ret = 0
    while (cur_total + outputs[cur] < 1):
        cur_total += outputs[cur]
        cur += 1
        k, nw = sim_opp(cur_total, cur)
        ret = max(ret, k + dp(nw, games-1))
    #print(s, ret)
    mem[(s,games)] = ret
    return ret
    
def backtrack(s, games):
    res = dp(s,games)
    cur = s
    cur_total = 0
    ct = 0
    while (cur_total + outputs[cur] < 1):
        ct += 1
        cur_total += outputs[cur]
        cur += 1
        k, nw = sim_opp(cur_total, cur)
        if (res == k + dp(nw,games-1)):
            return ct
    

outputs = [r2.random() for i in range(6000)]
print(dp(0, 1337-games))

cur = 0

for i in range(1337-games):
    
    num = backtrack(cur, 1187-i)
    cur_total = 0
    r.recvuntil(b"[")
    f = float(r.recvuntil(b"]")[:-1].decode())
    assert(abs(f - outputs[cur] ) < 1e-5)
    cur += 1
    cur_total += f
    for _ in range(num-1):
        r.sendline(b"h")
        r.recvuntil(b"[")
        f = float(r.recvuntil(b"]")[:-1].decode())
        assert(abs(f - outputs[cur] ) < 1e-5)
        cur_total += outputs[cur]
        cur += 1
    
    
    r.sendline(b"s")
    RES = r.recvuntil(b"Score: ").decode()
    search = re.findall('\[(.*)\]', RES, re.IGNORECASE)
    for x in search:
        assert(abs(float(x) - outputs[cur] ) < 1e-5)
        cur += 1
        
    score = r.recvline()[:-1].decode()
    myscore = int(score.split("-")[0])
    if (i%20 == 0):
        print(score)
    if (myscore >= 800):
        r.interactive()
```
