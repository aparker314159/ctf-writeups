# Intro

Over the weekend, I participated in Maple CTF as part of my university's CTF team. I didn't solve too many challenges, but I figured I'd do a writeup of one of them that I particularly enjoyed.
As with all of the writeups I do, I'm going to try to walk through my thought process on top of providing a solution to the challenge.

# The Challenge

We're provided with a single script that runs on a remote server. The script is as follows:
```python
from random import Random
from secret import FLAG
import signal

class Coin:
    def __init__(self, coin_id):
        self.random = Random(coin_id)
        self.flips_left = 0
        self.buffer = None

    def flip(self):
        if self.flips_left == 0:
            self.buffer = self.random.getrandbits(32)
            self.flips_left = 32
        res = self.buffer & 1
        self.buffer >>= 1
        self.flips_left -= 1
        return res

if __name__ == "__main__":
    signal.alarm(60)
    print("Welcome to Maple Betting!")
    print("We'll be betting on the outcome of a fair coin flip.")
    print("You'll start with $1 - try to make lots of money and you'll get flags!")

    game_id = input("Which coin would you like to use? ")
    num_rounds = input("How many rounds do you want to go for? ")
    num_rounds = int(num_rounds)
    if num_rounds > 20_000_000:
        print("Can't play that long, I'm afraid.")
        exit(1)

    print("Alright, let's go!")
    coin = Coin(int(game_id, 0))
    money = 1
    for nr in range(num_rounds):
        money += [1, -1][coin.flip()]
        if money <= 0:
            print(f"Oops, you went broke at round {nr+1}!")
            exit(1)

    print(f"You finished with ${money} in the pot.")
    if money < 18_000:
        print("At least you didn't go broke!")
    elif money < 7_000_000:
        print(f"Pretty good!")
    else:
        print(f"What the hell?! You bankrupted the casino! Take your spoils: {FLAG}")
```

In short, the script seeds a random number generator with a user-supplied seed, then generates up to 20,000,000 bits from that generator. For every 0, the `money` variable is incremented, and for every 1 it is decremented.
We need `money` to always remain positive, and end at a value over 7,000,000. This means our random number generator must be *heavily* biased towards 0. We're allowed to choose the seed here, but that's it.
So we need to find a seed that produces an output weighted towards zero.

# How Python's RNG works
The first order of business is to figure out how Python's RNG works, so to see how we can manipulate it.

From the [documentation](https://docs.python.org/3/library/random.html), Python's default rng is a [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister). Particularly, it uses the MT19337 algorithm, which consists
of an internal state of 624 32-bit integers. I wasn't too familiar with the details of the algorithm before this challenge, so I took the opportunity to read the Wikipedia page on a Mersenne Twister to see if there 
were any insights from it.

Indeed, one of the bullets in the "Disadvantages" section pretty much tells us exactly what we want:

"Contains subsequences with more 0's than 1's. This adds to the poor diffusion property to make recovery from many-zero states difficult."

If we find a seed that puts the internal state into one with lots of zeroes, then it will take a long time for the generator to stop being biased towards 0. Hopefully, this "long time" will be more than 20,000,000 bits of output,
in which case we'll be able to solve the challenge.

## How does a Mersenne Twister work?

The algorithm behind a mersenne twister is pretty neat, but also a little bit out of scope of this writeup.
There are a few key points that I'll be using in this challenge, so I figured I'd explain what the general ideas are.

The twister consists of an internal state buffer of 624 32-bit integers, as well as an index variable `i`. To generate a 32-bit integer, the MT takes the `i`th member of the state buffer,
applies some bit shifts and bit ANDs to it, and returns that. The index is then incremented. If the index reaches 624, the generator performs a "twist" and resets the index to 0.

The twist is where some magic happens, involving more bit shifts and XORs. It generates a new set of 624 integers as the internal state, allowing for 624 more integers to be generated before another twist.

Both the process of generating an integer from the state and the twisting itself consist mostly of bitshifts, ANDs, and XORs. This seems to confirm that a state with a lot of zeroes will result in a lot of bias towards zero in the
output, since `0 AND 0 == 0` and `0 XOR 0 == 0`.

# Making some zeroes
Obviously, we should probably double check that a state full of zeroes results in an output full of zeroes.
Python allows us to inspect and set the internal state of its Mersenne Twister using `random.getstate` and `random.setstate`. 


Let's try to start with the best case scenario: what if we make the state entirely zero?

```python
>>> random.setstate((3, tuple([0 for _ in range(624)] + [624]), None)) # the last 624 sets the index to 0
>>> [random.getrandbits(32) for _ in range(1000)]
(all zeroes)
>>> random.getstate()
(more zeroes)
```

Cool! If the state buffer is all zeroes, it remains all zeroes even after a twist. That means we'll only get zeroes, which is exactly what we need!

## Except...
We can't set the state buffer directly. We need to use a seed to do it. And there's no obvious way that a seed gets converted to a state. It's not like the bits of the number are directly read into the state buffer - in that
case `random.seed(0)` would give a state buffer of all zeroes, which is not the case.

There Python documentation didn't seem to give an explanation of how a seed is converted into a state, so I had to resort to looking at the actual CPython code.

# Exploring the insides of the snake

Here is the relevant code for `random.seed()`, which is found [here](https://github.com/python/cpython/blob/14098b78f7453adbd40c53e32c29588611b7c87b/Modules/_randommodule.c).
```C
static int
random_seed(RandomObject *self, PyObject *arg)
{
    int result = -1;  /* guilty until proved innocent */
    PyObject *n = NULL;
    uint32_t *key = NULL;
    size_t bits, keyused;
    int res;

    if (arg == NULL || arg == Py_None) {
       if (random_seed_urandom(self) < 0) {
            PyErr_Clear();

            /* Reading system entropy failed, fall back on the worst entropy:
               use the current time and process identifier. */
            random_seed_time_pid(self);
        }
        return 0;
    }

    /* This algorithm relies on the number being unsigned.
     * So: if the arg is a PyLong, use its absolute value.
     * Otherwise use its hash value, cast to unsigned.
     */
    if (PyLong_CheckExact(arg)) {
        n = PyNumber_Absolute(arg);
    } else if (PyLong_Check(arg)) {
        /* Calling int.__abs__() prevents calling arg.__abs__(), which might
           return an invalid value. See issue #31478. */
        _randomstate *state = _randomstate_type(Py_TYPE(self));
        n = PyObject_CallOneArg(state->Long___abs__, arg);
    }
    else {
        Py_hash_t hash = PyObject_Hash(arg);
        if (hash == -1)
            goto Done;
        n = PyLong_FromSize_t((size_t)hash);
    }
    if (n == NULL)
        goto Done;

    /* Now split n into 32-bit chunks, from the right. */
    bits = _PyLong_NumBits(n);
    if (bits == (size_t)-1 && PyErr_Occurred())
        goto Done;

    /* Figure out how many 32-bit chunks this gives us. */
    keyused = bits == 0 ? 1 : (bits - 1) / 32 + 1;

    /* Convert seed to byte sequence. */
    key = (uint32_t *)PyMem_Malloc((size_t)4 * keyused);
    if (key == NULL) {
        PyErr_NoMemory();
        goto Done;
    }
    res = _PyLong_AsByteArray((PyLongObject *)n,
                              (unsigned char *)key, keyused * 4,
                              PY_LITTLE_ENDIAN,
                              0); /* unsigned */
    if (res == -1) {
        goto Done;
    }

#if PY_BIG_ENDIAN
    {
        size_t i, j;
        /* Reverse an array. */
        for (i = 0, j = keyused - 1; i < j; i++, j--) {
            uint32_t tmp = key[i];
            key[i] = key[j];
            key[j] = tmp;
        }
    }
#endif
    init_by_array(self, key, keyused);

    result = 0;

Done:
    Py_XDECREF(n);
    PyMem_Free(key);
    return result;
}

```

In short, if we supply a long to the random.seed function, it converts it to an array or 32-bit ints, then passes it to the `init_by_array` function to initialize the state buffer. So let's peek at the `init_by_array` and 
see what it does:

```C
static void
init_by_array(RandomObject *self, uint32_t init_key[], size_t key_length)
{
    size_t i, j, k;       /* was signed in the original code. RDH 12/16/2002 */
    uint32_t *mt;

    mt = self->state;
    init_genrand(self, 19650218U);
    i=1; j=0;
    k = (N>key_length ? N : key_length);
    for (; k; k--) {
        mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525U))
                 + init_key[j] + (uint32_t)j; /* non linear */
        i++; j++;
        if (i>=N) { mt[0] = mt[N-1]; i=1; }
        if (j>=key_length) j=0;
    }
    for (k=N-1; k; k--) {
        mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941U))
                 - (uint32_t)i; /* non linear */
        i++;
        if (i>=N) { mt[0] = mt[N-1]; i=1; }
    }

    mt[0] = 0x80000000U; /* MSB is 1; assuring non-zero initial array */
}


static void
init_genrand(RandomObject *self, uint32_t s)
{
    int mti;
    uint32_t *mt;

    mt = self->state;
    mt[0]= s;
    for (mti=1; mti<N; mti++) {
        mt[mti] =
        (1812433253U * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti);
        /* See Knuth TAOCP Vol2. 3rd Ed. P.106 for multiplier. */
        /* In the previous versions, MSBs of the seed affect   */
        /* only MSBs of the array mt[].                                */
        /* 2002/01/09 modified by Makoto Matsumoto                     */
    }
    self->index = mti;
    return;
}

```

Here, you might spot some trouble. The first entry of the state buffer is *always* set to `0x80000000`, which means that our original idea of finding a seed to make the state buffer all zeroes won't work.
However, we can settle for the next best scenario, which is a state buffer where everything is zero except the first entry, which is 1 bit away from zero. This turns out to be sufficient for the challenge.

With the code to turn a seed into a state array, we can now hopefully reverse it to get a seed that gives us what we want.

# Inverting the Twister

This is the fun part. First, let's copy the code over and make it into a standalone program so we can more easily experiment with it.

```C

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

#define N 624

struct RandomObject {
    uint32_t state[624];
    uint32_t index;
};

typedef struct RandomObject RandomObject;

/* initializes mt[N] with a seed */
static void
init_genrand(RandomObject *self, uint32_t s)
{
    int mti;
    uint32_t *mt;

    mt = self->state;
    mt[0]= s;
    for (mti=1; mti<N; mti++) {
        mt[mti] =
        (1812433253U * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti);
    }
    self->index = mti;
    return;
}

static void
init_by_array(RandomObject *self, uint32_t init_key[], size_t key_length)
{
    size_t i, j, k;       /* was signed in the original code. RDH 12/16/2002 */
    uint32_t *mt;

    mt = self->state;
    init_genrand(self, 19650218U);
    i=1; j=0;
    k = (N>key_length ? N : key_length);
    for (; k; k--) {
        mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525U))
                 + init_key[j] + (uint32_t)j; /* non linear */
        i++; j++;
        if (i>=N) { mt[0] = mt[N-1]; i=1; }
        if (j>=key_length) j=0;
    }
    

    for (k=N-1; k; k--) {
        mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941U))
                 - (uint32_t)i; /* non linear */
        i++;
        if (i>=N) { mt[0] = mt[N-1]; i=1; }
    }

    mt[0] = 0x80000000U; /* MSB is 1; assuring non-zero initial array */
}

int main() {
    RandomObject ro;
    uint32_t* key = calloc(624, sizeof(uint32_t));
    
    /* Set our key here */
    
    init_by_array(&ro, key, 624);
    
    for (int i = 0; i < N; i++) {
        printf("%u, ", ro.state[i]);
    }
}
```

Now, we work backwards.

## The second loop
Ideally, we want the state to be all zeroes after the second loop, though really the first entry of the state buffer can be anything since it gets changed to `0x80000000` anyways.

Let's narrow in on this line:
```C
mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941U))
         - (uint32_t)i; /* non linear */
```
Our goal is to get the quantity `(mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941U)) - (uint32_t)i` to be zero. If we did everything correctly, then `mt[i-1]` should already be zero, unless this is the first
iteration of the loop. We'll handle that case in a second, but for now let's assume it is. That simplifies our expression drastically to just `mt[i] - i`. Thus, having `mt[i] = i` going into the loop will zero out the coefficient.

Now, we deal with the base case of the first iteration. In this case, `mt[i-1]` is not necessarily zero, so we need to cancel it out. It turns out when we enter the loop `i = 2`, so `mt[i-1]` will be one.
We can thus simplify our expression down to `mt[2] ^ 1566083941 - 2`, which means that setting `mt[2] = 1566083943` will zero out that entry on the first iteration of the loop.

So going into the second loop, we want our array to be of the form `[0,1,1566083943,3,4,5,6, ... ,623]`. 

## The first loop
Let's look at the first loop in `init_by_array` now:
```
init_genrand(self, 19650218U);
i=1; j=0;
k = (N>key_length ? N : key_length);
for (; k; k--) {
    mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525U))
             + init_key[j] + (uint32_t)j; /* non linear */
    i++; j++;
    if (i>=N) { mt[0] = mt[N-1]; i=1; }
    if (j>=key_length) j=0;
}
```

First, `init_genrand` is called with a fixed seed, essentially setting the mt state buffer to some random but known state. From there, we iterate over `mt`, setting `mt[i]` to 
`(mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525U)) + init_key[j] + j`

The key (no pun intended) thing to notice here is that the key is simply added on to the state buffer, which makes controlling the state buffer easy.
First, let's define `targets` to be the array that we want going into the second loop.
If we set `init_key[j]` to simply be `-((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525U)) - j + targets[i]`, then when we add the two quantities together we're left with just `targets[i]` as the value for `mt[i]`.

We can do this in code with an auxiliary state buffer. Since we know the state of `mt` going into the loop, we can simulate the seed function and set the key accordingly.
```
RandomObject ro2;
init_genrand(&ro2, 19650218U);

int j = 0;
for (int i = 1; i < N; i++) {
    key[j] = -(ro2.state[i] ^ ((ro2.state[i-1] ^ (ro2.state[i-1] >> 30)) * 1664525U)) - j + targets[i];
    ro2.state[i] = (ro2.state[i] ^ ((ro2.state[i-1] ^ (ro2.state[i-1] >> 30)) * 1664525U))
             + key[j] + (uint32_t)j ;
    j++;
}
key[623] -= 1036999696; // set final key value
```

Note that the loop doesn't set the final key value properly, so we set it manually. The value 1036999696 was found simply by running the loop without the final key value set, and then taking the difference.

If we've done everything properly, the key value we get from this program will work.
```
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

#define N 624

struct RandomObject {
    uint32_t state[624];
    uint32_t index;
};

typedef struct RandomObject RandomObject;


uint32_t targets[624] = {0,1,1566083943,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,256,257,258,259,260,261,262,263,264,265,266,267,268,269,270,271,272,273,274,275,276,277,278,279,280,281,282,283,284,285,286,287,288,289,290,291,292,293,294,295,296,297,298,299,300,301,302,303,304,305,306,307,308,309,310,311,312,313,314,315,316,317,318,319,320,321,322,323,324,325,326,327,328,329,330,331,332,333,334,335,336,337,338,339,340,341,342,343,344,345,346,347,348,349,350,351,352,353,354,355,356,357,358,359,360,361,362,363,364,365,366,367,368,369,370,371,372,373,374,375,376,377,378,379,380,381,382,383,384,385,386,387,388,389,390,391,392,393,394,395,396,397,398,399,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,419,420,421,422,423,424,425,426,427,428,429,430,431,432,433,434,435,436,437,438,439,440,441,442,443,444,445,446,447,448,449,450,451,452,453,454,455,456,457,458,459,460,461,462,463,464,465,466,467,468,469,470,471,472,473,474,475,476,477,478,479,480,481,482,483,484,485,486,487,488,489,490,491,492,493,494,495,496,497,498,499,500,501,502,503,504,505,506,507,508,509,510,511,512,513,514,515,516,517,518,519,520,521,522,523,524,525,526,527,528,529,530,531,532,533,534,535,536,537,538,539,540,541,542,543,544,545,546,547,548,549,550,551,552,553,554,555,556,557,558,559,560,561,562,563,564,565,566,567,568,569,570,571,572,573,574,575,576,577,578,579,580,581,582,583,584,585,586,587,588,589,590,591,592,593,594,595,596,597,598,599,600,601,602,603,604,605,606,607,608,609,610,611,612,613,614,615,616,617,618,619,620,621,622,623};


/* initializes mt[N] with a seed */
static void
init_genrand(RandomObject *self, uint32_t s)
{
    int mti;
    uint32_t *mt;

    mt = self->state;
    mt[0]= s;
    for (mti=1; mti<N; mti++) {
        mt[mti] =
        (1812433253U * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti);
    }
    self->index = mti;
    return;
}

static void
init_by_array(RandomObject *self, uint32_t init_key[], size_t key_length)
{
    size_t i, j, k;       /* was signed in the original code. RDH 12/16/2002 */
    uint32_t *mt;

    mt = self->state;
    init_genrand(self, 19650218U);
    i=1; j=0;
    k = (N>key_length ? N : key_length);
    for (; k; k--) {
        mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1664525U))
                 + init_key[j] + (uint32_t)j; /* non linear */
        i++; j++;
        if (i>=N) { mt[0] = mt[N-1]; i=1; }
        if (j>=key_length) j=0;
    }


    for (k=N-1; k; k--) {
        mt[i] = (mt[i] ^ ((mt[i-1] ^ (mt[i-1] >> 30)) * 1566083941U))
                 - (uint32_t)i; /* non linear */
        i++;
        if (i>=N) { mt[0] = mt[N-1]; i=1; }
    }

    mt[0] = 0x80000000U; /* MSB is 1; assuring non-zero initial array */
}

int main() {
    RandomObject ro;
    uint32_t* key = calloc(624, sizeof(uint32_t));

    /* Set our key here */
    RandomObject ro2;
    init_genrand(&ro2, 19650218U);

    int j = 0;
    for (int i = 1; i < N; i++) {
        key[j] = -(ro2.state[i] ^ ((ro2.state[i-1] ^ (ro2.state[i-1] >> 30)) * 1664525U)) - j + targets[i];
        ro2.state[i] = (ro2.state[i] ^ ((ro2.state[i-1] ^ (ro2.state[i-1] >> 30)) * 1664525U))
                 + key[j] + (uint32_t)j ;
        j++;
    }
    key[623] -= 1036999696; // set final key value

    printf("Key: \n");
    for(int i = 0; i < N; i++) {
        printf("%u ", key[i]);
    }

    init_by_array(&ro, key, 624);

    printf("\n\nState: \n");
    for (int i = 0; i < N; i++) {
        printf("%u, ", ro.state[i]);
    }
}
```

# So, does it work?

Let's test it out! The key output by the program is still an array of 32-bit ints, but converting it is pretty easy, and gives us this:
```
0xc230a3f06f63458da31799827b37b66b56258fad6d9f4abe83b656d75039aa466cebe4069b45a9aa58e93c783fc680f4418983609647fe2054326d4aa9a06188b0f2faf737d0ffc160b133e1e01f264e99d5a1fd7d4023be33f7ed49542176243de356cd0cfb685ba1453824b8dd32467785e2aa2ad361cc6e68483ef79d3975d154fa154fd80cba2b98ddb1db4192aef398aa2ca421148c954b11b9064a3965c16ad46d3fe517cb53fc6f6394778ef1ebb497ad74102f662d48dc193914129deb8d816dbdf2c805e20f411be3d853e069c37534b51662b4e4f7b2307b6b4559b38d2260f244250db221655a89c8133cf4f081d60373d8a0bf322addc33ea21633c989bf45d9303864c65d06408cbdf76040560944091e12f57a22122711f266ab939a29c7eaa3d046f1bd461761b70e5173b7e23f3f8be4f1e78b6867d79af97d8b4f173d7f5ca15e516041b949596f62cca47119a3889be1b75e21078885ed8fb011c4e310d4c90cb916908e9b797a631096de1c8ae1d8e7d8f7d42010c9acfa74585a413fd19112b5c4c0a4fa64b269767c3e1f183d405391ce52eb4cde09c24e75e152f02d46edea20ea6d4c4edb515f41559a88f0a15861725d5c8c93e8f09d2236c97ca1c318fe0142ccba897ddcee14b14eff773a34d8e2adfa61ef4e47203c3ec3ab6a93c704d02d8ce6061b7fc17ea56f05ab7ec08d9ede71299873c3a02f97191f80116ced41e1db53db1e4f9caa5a6a86bb35c69f83af511e65ee4531ea4e3091ddf437441553b567cc2166d99c9b172f9d41372d8e1cfffc28337f1cede9a7f9403989fa7e466050b907bfd4bbe6be77f6e6a795836f06b3d87f057ad49c0e3fb15ee7005782d7fa6ac59879e5b056216dff18f8dfd26a12b60fc6c1a7c389094b638524ea341332b1c04f7283a405518872fd7f7512379b8c06543da5a6bdf77ceabe2b0a1775b3d3ca2a525b3f0ef6566d9ccb531ed8c70ac5dd179c55b337102d5fe22855c9dd0eda78ae89d61ccf7138054eac9bfda4e1b433bd9a9d8b42bc6d80b6b9bafa84301df7c81349ba20b92de6a07d4fe6b147d881049d1786e4e2cfcb4271a9ef776de67a7a3b22c69cde2b4bb7bfff5b74a39e0840f49ffaf71c8ed7be06a2fd6ada15ed583bb11f43833328128aae86c293743cdfcdf5942683ed9a12faf2cf29106d2515f31e7b3ab311ba479e42ce5c4f2997c6bff03816601a32454c595a25eb201210ef1dbf052f09068b4734ca14c78b529fb0d19ef1e4711e75ee208b932152b36bf4e1786acb9a1d8780dd003cf3317deeb1a717bf2f39540d1931003958693ea2b3420eb11a6407969647a0512f710f4cbb6e80f7487a22eff221a8d92cafbc25984e07077320aa0a29a5ed86d976dffffde8f1329395ec395f73b12a53d1dee3325d630806a67a91fd884dd08aa9f4d7b3f9de82357819fd5387e2f3e2247945efb87302f8af8dcb194c26ecc68c2f0cfc85bb567e25357916f471c42aa90570a0a299412ee2e0eeee4a90959388c1aeb7f612ce5724f6a77f4ca4bb654698a7f05523873fe70b9537529147ff18d476f34e87121e22537358500acf037c276b4d39e58e5a1c017c572f1ed4d5d74d2c3ccda2006b55e31246bb4770906e5ab3f3ea3f2187a429c3438fc27ae570bf39fb576ad70448a5519e51bbc81a878429790eb8500ab63cf07b0913dca24d291d7dfa63662e415859eb013103f5d1bd5072940b917792100919a5c0fe9036e9a4f4e84ceeb2d3e3456cada86b7bdb01a624a4ad0200acdb98fac04e6437d1be8b4300021090e27bc5b8a82321d0fcc5993eceac5688ee7bef3b6840624951fbd503e98a113b91e1e330b7abe30b8dd5d78e69dd5a2c5cf94f6d20ce9a63bfd0e0d84359f246f4ae373c7d7c072d64edb02ee6720584a98858b37abeb8e3505dbedb681a20ed7260291520a0e3042aa2b7fcf130831ec37f21710fc2ff2a784ce2f1986610f7db78a1fabb59f1f2ae72e64deacf4c11e37358f7379beaed89121b305e1cf8bf8423d57603269ae10fb1b3c4f67f1c7ef1ce0f010b2e8a74fb1f597a303bfd3762f6658bd602949bd687a237e54fd3ff5639789aa17af0270cb4f2f1132bcab6ed8c917d7a977bb39cf66221b6519c23c148331d0d712acd48e028a066511892c516dcb0ec0ac8db98896b179b2bff0ec92715e8ec5ab5282d7f548ef3f706ae1ac6d354e6b8cf3b30962cd49b998af43fc49e17254b4ae4c0dabda4ee8360215a72486b209d974aa27079d23e31ebf8f0d62f7af43222bf9450f07e1ce8048be131aa55b8752782a563151a4f0c71658dc77cefcf0669a47746fdf46d8e98f5b56e59831dcee875f2038cd7bff3cedb121bca32f55b706e982c47bf010cb336a70e829df61a2e8ffe57b5d652f0495f132377842eb646c814d8bb7ab2da4985d7f5e98d31f882015e271c520b4b2f42c82af9c8cb98149a850540c03ad0a9bb8711e13cc6355df41ef9e9ad44adc5da4c5658e41e9d94e6f40210c04579feb5aaad2a435f184e8a3bcf243e1b97e45f87095c8642f67e63f9d5036f1122849e37e99f7e29958f5cbf47004fa9c3e5a29cc53da9e05116f0016dd8dcffd78bf3e656c092a4c87d4a9f81153dbe35fe33309dde407587bc1fc7e5aeef630c0856bd4566ccedb6b016bbacae97a24c07a3958259b4567a09a03bba4aa49e3de6469c5c31aaa2348fe52a83155d99b00523c530a73140e6cb0c77c9217f437e2e142c04bf443b62b4fda667fe5e7a75ced70db0387a7e95b4fae41c210d656fa25cda5eb2214041a2dca52aa9ed5692f441f6b4490c3f5ac9f88e2c8f78ff5e058dc09d5f21a926680cb196a778fc6be1b6337bdcdcff9be3f2899087ed58a978dbfca49c4425374f6fdd847908a0d29a596995aa334a0d7674aecbeaf410a92a8b6ce62d801caf7796eed699f304e13571dd7e3faf5138bb54c503365672f4bd2e77711681af1efceb5bc81b0dcbd8e05ba60f45a7b1824ec5db1c2e49b82db896a28c24f5cff6f8ce34e5c736ee4f2791494e4e9535517d4e00e844033e101a61bc201831830ab3063799f928a6309fe898f00696ac02dea38c7445b064e4c2a5994ae342d16b6bdd086991293423efe2ca2b5eed550f7fde1187964b904974bd036da4bcc3589e34c638c1e67341b78ea086282f651db24ff95031e97f22f88081d51c58b7d6160bbc49b4d458c2d50639ffef26e35773cc5243c7c48a8827c6bea813385b076048ef50d7a2c1f9ac605c298f93c78075abd920a25e2e54e23815f379ea23da984a90b472bebb908303dfdfd01685477fbee0814e0c8f2fdc50598c58a8e6b3a1c268dd8be35a31b9f2044bb347beb5abf4bc1453684567baf8f2766437a0711777ad04d1db165bdb52815583ab2d64713908aa49bd073bc082411b7f319031398164528de598b05377b0c4c9d0a418e31e5457ac78ac934a5040d482a9587df58ff5d55490710a8422e9291e9aac0076f650
```

That's certainly a big number. But if we seed a random number generator in Python using it, we get...
```
>>> random.seed(key)
>>> random.getstate()
(3, (2147483648, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 624), None)
```

Huzzah! This seems to be the best state possible in terms of numbers of zero bits, so if this doesn't work with the program I don't know what would.

# One slight hiccup
I actually encountered a small problem when actually testing this out. This problem was entirely self-inflicted, but I'm including it in this writeup so if someone else encounters this problem down the line they might know
the fix.

In short, when I ran the server script locally, I simply pasted in the seed into the input and pressed enter. For some reason, my terminal (Konsole) didn't like that, and actually secret only submitted the first 4096 characters
of the input seed, causing me to lose on round zero. After a bit of hair-pulling trying to figure out what was going wrong, I eventually was able to work around it by using `pwntools` io to send the seed.

Once I verified it worked locally, I ran the script targetted on remote (and did the PoW), and got the flag: `maple{1nv3rt_m3rs3nne_tw1ster,bet,pr0f1t!!1!_0aa3a8efe77eaade}`

# Closing Thoughts
This challenge was a lot of fun. I dived into the CPython internals, learned about Mersenne Twisters, and did a little bit of thinking to find the input key (that probably could've been sped up by z3). Huge thanks to the Maple Bacon
team for running the CTF, and nneonneo for authoring this challenge.
