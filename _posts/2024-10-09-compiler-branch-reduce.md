---
date: 2024-10-09 10:26:03
layout: post
title: RRVM 编译器优化-窥孔优化： conditional branch 指令优化
subtitle: 
description: >-
    pass 实现思路原稿
image: >-
  /assets/img/uploads/rrvm.jpg
optimized_image: >-
  /assets/img/uploads/rrvm.jpg
category: hackedemic
tags:
  - rrvm
  - compiler optimization
  - peephole optimization
author: rosayxy
paginate: true
---
# 窥孔优化-conditional branch combining
注：这是在当时编译器比赛（全国大学生计算机系统能力大赛-编译系统设计赛）实现这个优化 pass 之前写的设计思路文档。**big credit to [Fuyuki](https://github.com/Fuyuky)**   
目的是当一个比较数为0时，用 conditional branch 和前面的 slt (等用于比较 set flags 的指令),xor 等指令合并，减少指令条数，从而提高性能    
[项目仓库](https://github.com/rrvm-project/SysYc)，主要与其中 commit c85253f 有关    

## 应用情况
考虑类似于下面的代码段
```
slt %3 , %1 , %3
....
bne %3, 0
```
可以被优化成以下语句
该情况有以下特征：
- 基本块以 conditional branch 指令结束，且该指令是一个（虚拟）寄存器和立即数 0,1 比较，从而进行跳转的指令，update 这种情况，立即数应该就是 x0 了     
- 被比较的（虚拟）寄存器的最后一次写操作是在比较语句中，类似于被设了一个 flag    
- 在写该寄存器和条件跳转之间，没有指令读该寄存器，该寄存器也不在 live_out 中

## 实现
我们的 branch 指令有这些：`Beq`,`Bne`,`Blt`,`Bge`,`Bltu`,`Bgeu`       
而以下为所有涉及的条件指令：      
- `slti`->`blt`
- `sltiu`->`bltu`
- `sltiw` 这能转化吗，gpt 了一波没找到对应，update 这玩意好像没 riscv instruction 会用到
- `sltu`->`bltu`
- `slt`->`blt`
- `seqz`->`beq`
- `snez`->`bne`

就按照这个转化一波应该就行了    
实现位置：    
在 instruction scheduling 前做    

## 考虑如下情况
```asm

    xor s1, s1, s3        # xor %3, %1, %2
    seqz s1, s1           # seqz %4, %3
    bne s1, x0, L_12      # bne %4, x0, L_12
                             
```

```asm
  bne s3,s1,L_12

```

```asm
    seqz s1, s1
    bne s1, x0, L_3
```
被优化为
```asm
  beq x0,s1,L_3
```
但是考虑 xori 指令 和 slti 指令，都可以改成先把那条指令替换为 li %33, imm 然后 cbranch %33, %4 这样子   