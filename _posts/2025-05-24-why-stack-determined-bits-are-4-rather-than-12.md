---
date: 2025-05-24 10:21:56
layout: post
title: Why do stack variables have only the low 4 bits fixed
subtitle: rather than 12 bits
description: >-
    exploring stack randomization beyond aslr
image: >-
  /assets/img/uploads/environ.png
optimized_image: >-
  /assets/img/uploads/environ.png
category: hackedemic
tags:
  - stack randomization
  - aslr
  - kernel implementation
author: rosayxy
paginate: true
---
这周打比赛遇到了一个栈题，需要爆破栈地址的第二个 hex number，也就是 4 ~ 7 bits，这就引出了本人一直有点疑惑的问题：为什么栈变量的低 4 bits 是固定的，而不是 12 bits？因为我们知道的 aslr 是以页力度对齐的，所以想知道我们 OS 在它的基础上，对栈地址又做了什么样的随机化   
在 google 上搜了一波，发现大部分说法都是只提到两点：1. aslr 2. 栈地址必须 16 字节对齐，否则会出锅，而对上述问题没有很好的回答，所以就决定自己动手试一试了        
嗯 首先提一句，为什么栈随机化是低4 bit 固定的，因为它要保证 16 byte 的 alignment，不然的话，像 `movaps` 这种要求栈 16 字节对齐的指令会挂掉    

## determining the part of stack which is randomized

拿随便一个程序简单测了一下，在输出栈上内容的时候，发现打印了较多环境变量的字符串    
而多年的 pwn 经验告诉我们， environ pointer 到某个函数栈帧的偏移是固定的，而 environ pointer 存的是环境变量字符串的初始地址    
嗯 其中的 environ pointer 就是指你挂 gdb 上去， `p (long long*)environ` 所得到的输出，也是一般用来 leak 栈地址的值
所以我们进行一个简单的二分，看如下的哪个部分会被随机化： 1. 环境变量字符串到栈 segment 的上界的距离 2. environ pointer 到环境变量字符串的距离    

多次测试发现：**environ pointer 到环境变量字符串的距离会被随机化！环境变量字符串到栈 segment 的上界的距离在固定机子上多次测量结果不变！**    
就像是下面一次调试的截图，那两个红色箭头的距离是会变的hhh   
![alt_text](/assets/img/uploads/environ_output.png)

并且输出environ pointer 到环境变量字符串的内存，发现有大段的空白区域，说明有大概率是刻意而为的随机化    

## kernel implementation - stack randomization with page granularity
一开始拷打了一波 claude，让它帮我找是哪个内核函数对栈地址进行了随机化，找到的是 [randomize_stack_top](https://elixir.bootlin.com/linux/v6.6.70/source/mm/util.c#L322) 函数，它是在 [load_elf_binary](https://elixir.bootlin.com/linux/v6.6.70/source/fs/binfmt_elf.c#L823) 函数中调用的，该函数的目的是拿到初始的栈地址（由宏定义），然后加/减一个随机的页对齐的值，来实现栈地址的随机化   
```c
#ifndef STACK_RND_MASK
#define STACK_RND_MASK (0x7ff >> (PAGE_SHIFT - 12))     /* 8MB of VA */
#endif

unsigned long randomize_stack_top(unsigned long stack_top)
{
	unsigned long random_variable = 0;

	if (current->flags & PF_RANDOMIZE) {
		random_variable = get_random_long();
		random_variable &= STACK_RND_MASK;
		random_variable <<= PAGE_SHIFT;
	}
#ifdef CONFIG_STACK_GROWSUP
	return PAGE_ALIGN(stack_top) + random_variable;
#else
	return PAGE_ALIGN(stack_top) - random_variable;
#endif
}
```

该操作完，栈地址还是一个页对齐的值   

## kernel implementation - stack randomization with 4 bits fixed

那我们去找 kernel 是在哪里把栈上 environ 指针初始化的，经过一番 prompt 和搜索，找到了 [create_elf_tables](https://elixir.bootlin.com/linux/v6.6.92/source/fs/binfmt_elf.c#L156) 函数，该函数开头就调用了 [arch_align_stack](https://elixir.bootlin.com/linux/v6.6.92/source/arch/x86/kernel/process.c#L1029) 函数，而看到该函数做了我们一直在找的低 4 bits 对齐的随机化操作，代码如下：
```c
// https://elixir.bootlin.com/linux/v6.6.92/source/arch/x86/kernel/process.c#L1029
unsigned long arch_align_stack(unsigned long sp)
{
	if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
		sp -= get_random_u32_below(8192);
	return sp & ~0xf;
}
```

在读代码的时候，发现该函数在随机化 sp 之后，确实有把栈上 environ 和 argv 的地址依次设置为栈上环境变量字符串的地址，如下段代码所示    
```c
// https://elixir.bootlin.com/linux/v6.6.92/source/fs/binfmt_elf.c#L293
#ifdef CONFIG_STACK_GROWSUP
	sp = (elf_addr_t __user *)bprm->p - items - ei_index;
	bprm->exec = (unsigned long)sp; /* XXX: PARISC HACK */
#else
	sp = (elf_addr_t __user *)bprm->p;
#endif
/* Now, let's put argc (and argv, envp if appropriate) on the stack */
	if (put_user(argc, sp++))
		return -EFAULT;

	/* Populate list of argv pointers back to argv strings. */
	p = mm->arg_end = mm->arg_start;
	while (argc-- > 0) {
		size_t len;
		if (put_user((elf_addr_t)p, sp++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return -EINVAL;
		p += len;
	}
	if (put_user(0, sp++))
		return -EFAULT;
	mm->arg_end = p;

	/* Populate list of envp pointers back to envp strings. */
	mm->env_end = mm->env_start = p;
	while (envc-- > 0) {
		size_t len;
		if (put_user((elf_addr_t)p, sp++))
			return -EFAULT;
		len = strnlen_user((void __user *)p, MAX_ARG_STRLEN);
		if (!len || len > MAX_ARG_STRLEN)
			return -EINVAL;
		p += len;
	}
```
所以就可以知道，栈上 environ pointer 的地址是通过 `arch_align_stack` 函数来随机化的   

然后为什么做这步，其实初始的想法是进一步增强栈的安全性，因为栈溢出漏洞通常来说，利用难度还是比堆漏洞低一些的   

但是看 [注释](https://elixir.bootlin.com/linux/v6.6.92/source/fs/binfmt_elf.c#L178) 里出现了这个，应该是为了防止并行等情况下，过于频繁访问同一个 L1 cache 的 cache line，导致该 cache line 被频繁换入换出造成的开销   
> In some cases (e.g. Hyper-Threading), we want to avoid L1 evictions by the processes running on the same package. One thing we can do is to shuffle the initial stack for them.

顺手看了一下，把环境变量字符串放到栈上的函数在比较前的地方，是被 `kernel_execve` 函数中的 `copy_strings_kernel(bprm->envc, envp, bprm)` 做的，在比较前面的地方，所以必然在咱们 create_elf_tables 函数前   
## 结论
嗯 所以就是这样
