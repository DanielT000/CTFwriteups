## WeirdMachine


> You're interviewing for a CS major at Hogwarts.

> "Here at Hogwarts, our computers are a bit... different. Can you help us write a few programs on our WeirdMachine™?"

> Architecture:
```
The WeirdMachine is a collection of up to 10 smaller computers, each with 10 registers storing values from -1000 to 1000.
At the beginning of the program, we start off with only 1 computer, and its first two registers R0 and R1 are loaded with the program inputs.
```
> Instructions:
```    
SET x y: Set Rx to the value y.
ADD x y: Set Rx to the value of Rx + Ry.
NEG x: Clone the current computer, and add this clone to the collection of computers within the WeirdMachine. In the cloned computer, Rx is multiplied by -1.
JIZ x y: If Rx == 0, jump to instruction y. Instructions start from index 0.
JNZ x y: If Rx != 0, jump to instruction y. Instructions start from index 0.
HALT x: Stop the program. The output of the program is the value of Rx.
```
> All cloned computers as a result of NEG will run in parallel (i.e. run one instruction per tick). The first computer that HALTs will return the answer to the entire program, regardless of whether other computers are still running.

> The challenge: Write a script that performs R0 * R1.

We are given a programming challenge in a magical language, and we are asked to perform multiplication of two numbers stored in `R0` and `R1` to get the flag.

Firstly, we know that multiplication is just repeated addition, so we can split our cases into the case where `R0` is non-negative and the case where `R0` is negative.


### Case 1: `R0` non-negative
In this case, we can run a simple loop to add the value in `R1` to some sum variable (we will use `R2`) `R0` times.
In each iteration, we decrement `R0`, add `R1` to `R2`, and continue the loop if `R0` is not zero.

```
ADD 9 0          # store the value of R0 in R9 to be used so we can keep it for later
SET 2 0          # our current sum
SET 3 -1         # just stores -1
ADD 9 3          # subtract 1 from R9
ADD 2 1          # add value of R1 to sum in R2
JNZ 9 3          # if R9 is zero, we are done, else start again from ADD 9 3
HALT 2           # return the sum
```

### Case 2: `R0` negative
If `R0` is negative, the above solution will actually never terminate as `R0` will never reach 0.
If we negate `R0` and clone it, we can run the same code as above which will terminate because the new `R0` will be positive.
We will also need to negate the result we get if we are in this "negated clone".

To determine if we are in a "negated clone", we can check if the sum of our supposedly negated value and our original value is equal to 0.

The following pseudocode will negate `R0`, and then determine if we are in the original or the "negated clone".
```
ADD 4 0        # store value of R0 in R4
NEG 4          # clone a machine where R4 is negated
SET 9 0         
ADD 9 4         
SET 2 0        # do the same loop as above
SET 3 -1       
ADD 9 3        
ADD 2 1       
JNZ 9 3        
ADD 5 0        # create a new variable R5 = R0 + R4
ADD 5 4
JIZ 5 {x}      # if R5 is zero, we are in the negated clone (R4 = -R0), so we jump somewhere else to negate the result
HALT 2         # else we return the result as usual
```

After this, we will also need to negate the result, and we will do this similarly to the way we negated `R0`.
```
ADD 6 2        # store value of R2 in R6
NEG 6          # clone a machine where R6 is negated
ADD 7 2        # create a new variable R7 = R2 + R6
ADD 7 6
JNZ 7 {DIE}    # if R7 is not zero, we are not in the negated clone, so we jump to an infinite loop so the original will not return anything
HALT 6         # else we are in the negated clone, so we return R6 = -R2, the negated result.
SET 8 0        # the start of the infinite loop (DIE)
JIZ 8 {DIE}    
```

Final solution:
```
ADD 4 0
NEG 4
SET 9 0
ADD 9 4
SET 2 0
SET 3 -1
ADD 9 3
ADD 2 1
JNZ 9 6
ADD 5 0
ADD 5 4
JIZ 5 13
HALT 2
ADD 6 2
NEG 6
ADD 7 2
ADD 7 6
JNZ 7 19
HALT 6
SET 8 0
JIZ 8 19
```

Flag: `SEE{und3r6r4d_4dm15510n5_4r3_cr4zy_7fc37a510e35d46075f70325295f4526}`
