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

In this challenge, we play a modified game of [blackjack](https://en.wikipedia.org/wiki/Blackjack) with the server, where we obtain outputs between 0 and 1 and try to not exceed a sum of 1 (busting) while also beating the dealer's sum. 
The goal is to win 800 out of 1337 games.

### Part 1: Predicting random numbers
Upon inspecting the source, we see that the outputs are obtained via the `random.random()` function.

A quick look at the `random` library gives us this warning:
> Warning: The pseudo-random generators of this module should not be used for security purposes. For security or cryptographic uses, see the secrets module.

The `random` library uses the Mersenne Twister as the generator, which is not cryptographically secure. It well known that given 624 known 32-bit outputs, we can predict future outputs.

Usually, I use [this library by kmyk](https://github.com/kmyk/mersenne-twister-predictor) but this only provides an implementation for the function `getrandbits(32)`, while this challenge uses `random()`.

Thankfully, I also found [this library by icemonster](https://github.com/icemonster/symbolic_mersenne_cracker) that allows us to enter in partial outputs from the random generator and it will help us find the best guess. 

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

I found that giving around 1300 partial outputs (i.e 650 floats) to the `Untwister` was enough to correctly predict the rest of the outputs, so we will have to play the game normally for around 200 rounds, trying to obtain as many floats as possible. 

A nice optimisation I found to obtain more floats is that it is always optimal to hit while our current total is less than 0.5. 

This is because:
1) If we do not bust, we can continue playing and getting outputs, which is good.
2) If we do bust, that means that we got a float > 0.5 (because our current total was < 0.5).
    - If we had stood instead, the dealer would have beat us using only 1 float (the same one we got).
    - This reveals the same number of outputs anyway.

As such, my strategy to obtain outputs consisted of hitting until my current total was > 0.5, and then standing.


### Part 2: Dynamic programming

Now that we have cracked the random number generator, we will know all future outputs. We can then plan out our moves to win as many games as possible.

This is also possible because we know the dealer's algorithm from the source, which is to keep hitting until either they bust or they beat our total. 

This means that we can 
    1) Simulate hitting x times
    2) If we do not bust, simulate the dealer's moves
    3) Calculate the outcome of the round (we win if and only if we do not bust and the dealer does)
    
After each round, the "starting point" for the next round is different, and we can solve this subproblem similarly. We can repeat this until we have exhausted all our remaining games (the base case).

This can be done with [dynamic programming](https://en.wikipedia.org/wiki/Dynamic_programming) and backtracking, implemented in the `dp()` and `backtrack()` methods with memoisation.

Solve script:
```python
from z3 import *
from random import Random
from itertools import count
import time
import logging
import sys
from pwn import *
sys.setrecursionlimit(4000)   # for the dp to run

logging.basicConfig(format='STT> %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

SYMBOLIC_COUNTER = count()

class Untwister:           # copied from icemonster's repo: https://github.com/icemonster/ymbolic_mersenne_cracker
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

# Part 1

def parse_float(random_num):                # each float is generated from two 32-bit outputs
    random_num = int(random_num*(1<<53))
    x1 = random_num >> 26
    x2 = random_num % (1<<26)
    ut.submit(format(x1,"08b") + '?'*5)
    ut.submit(format(x2,"08b")+ '?'*6)
    
def read_float():                           # receive float outputs from interaction
    r.recvuntil(b"[")
    return float(r.recvuntil(b"]")[:-1].decode())

r = remote("fun.chall.seetf.sg",30001)
ut = Untwister()    
ct = 0
games = 0

while (ct <= 1300):                         # obtain around 1300 outputs
    cur_total = 0
    f = read_float()
    parse_float(f)
    cur_total += f
    ct += 2                                 # each float gives us 2 outputs
    
    while (cur_total < 0.5):                # keep hitting while our total is less than 0.5 to maximise number of floats we can get
        r.sendline(b"h")
        f = read_float()
        parse_float(f)
        cur_total += f
        ct += 2
    
    r.recvline()
    x = r.recvuntil(b" ")[:-1].decode()
    if (x != "You"):                        # if we did not bust, we can stand, the dealer will play and we will get more floats
        r.sendline(b"s")
        RES = r.recvuntil(b"Score: ").decode()
        search = re.findall('\[(.*)\]', RES, re.IGNORECASE) # extract the floats from the dealer's turn
        for x in search:
            parse_float(float(x))
            ct += 2
    else:
        RES = r.recvuntil(b"Score: ").decode()
        
    score = r.recvline()[:-1].decode()
    games += 1
    if (games % 20  == 0):
        print(score)                        # progress check
        
print(ct)
r2 = ut.get_random()

# Part 2

def sim_opp(cur_total, cur):                # simulate the opponent's moves, 
                                              given that the outputs start from index cur and we have a sum of cur_total.
    opp_total = 0
    opp_cur = cur
    while (opp_total < cur_total):          # they keep hitting until they beat our total
        opp_total += outputs[opp_cur]
        opp_cur += 1
    if (opp_total > 1):                     # if they bust, we win
        return 1, opp_cur
    else:
        return 0, opp_cur

mem = {}

def dp(s, games):
    if (games == 0): return 0               # base case
    if ((s, games) in mem):                 # memoisation
        return mem[(s, games)]
    cur = s
    cur_total = 0
    ret = 0
    while (cur_total + outputs[cur] < 1):   # simulate all possible number of times to hit while not busting
        cur_total += outputs[cur]
        cur += 1
        k, nw = sim_opp(cur_total, cur)     # simulate the opponent's moves, get the result and the new starting point
        ret = max(ret, k + dp(nw, games-1)) # recurse to the next round and try to maximum number of wins
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
        if (res == k + dp(nw,games-1)):     # if this gives us the optimal solution we calculated earlier
            return ct
    

outputs = [r2.random() for i in range(6000)]   # predict future outputs
print(dp(0, 1337-games))                       # dp to find the max number of rounds we can win amongst the remaining rounds

cur = 0

for i in range(1337-games):                    # play remaining games optimally
    
    num = backtrack(cur, 1337-games-i)         # backtrack to find optimal number of times to hit
    cur_total = 0
    f = read_float()
    assert(abs(f - outputs[cur] ) < 1e-5)      # ensure we predicted correctly
    cur += 1
    cur_total += f
    for _ in range(num-1):
        r.sendline(b"h")
        f = read_float()
        assert(abs(f - outputs[cur] ) < 1e-5)  # ensure we predicted correctly
        cur_total += outputs[cur]
        cur += 1
    
    r.sendline(b"s")
    RES = r.recvuntil(b"Score: ").decode()
    search = re.findall('\[(.*)\]', RES, re.IGNORECASE)
    for x in search:
        assert(abs(float(x) - outputs[cur]) < 1e-5) # ensure we predicted correctly
        cur += 1
        
    score = r.recvline()[:-1].decode()
    myscore = int(score.split("-")[0])
   
    if (i%20 == 0):                            # progress check
        print(score)
        
    if (myscore >= 800):                       # we win, get flag
        r.interactive() 
```

Flag: `SEE{1337_card_counting_24ca335ed1cabbcf}`
