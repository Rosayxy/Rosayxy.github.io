---
date: 2024-10-09 10:24:03
layout: post
title: RRVM 编译器优化-窥孔优化：la 指令替换
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
# peephole optimization: qword load
注：这是在当时编译器比赛（全国大学生计算机系统能力大赛-编译系统设计赛）实现这个优化 pass 之前写的设计思路文档。**big credit to [Fuyuki](https://github.com/Fuyuky)**   
目的是用 la 伪指令的拆分和优化，减少指令条数，从而提高性能    
[项目仓库](https://github.com/rrvm-project/SysYc)，主要与其中 commit 365c37c 有关    
所以真的很喜欢写窥孔优化！实现起来很轻巧，然后效果也都有稳定提升 ~
riscv 的 la 指令为一条伪指令，可以被如下的指令序列替换：
```asm

la %1, symbol

auipc %1, %pcrel_hi(symbol)
addi  %1, %1, %pcrel_lo(symbol)

```

```asm
lui   %1, %hi(symbol)           # %hi(symbol) 为 PhysReg 到时候记得加接口 ~
addi  %1, %1, %lo(symbol)       
```
## 算法实现
以绝对寻址为例，我们先看例子
```asm


la %1, sym
lw %2, 0(%1)
// calculations with %2....
sw %32, 0(%1)


```
将第一条指令如下转换
```asm
lui %1, %hi(sym)
addi %1, %1, %lo(sym)
lw %2, 0(%1)
// calculations with t1
sw %3, 0(%1)
```
可以看到，addi 这条指令并非必须，上述代码可以替换如下
```asm

lui %1, %hi(sym)
lw %2, %lo(sym)(%1)
// calculations with %2
sw %3, %lo(sym)(%1)


```
所以我们有如下优化思路
- 对于所有 la 指令，我们首先进行以下判断：
  - 和它相关的所有 load store 指令的 offset(base) 寻址中的 offset 是否为 0
  - 然后它 la 到的寄存器在后续的指令中不被读
  - 然后我们以基本块为单位判断，所以就是说，la 到的寄存器在本基本块后续的指令中不被读，且不在 liveout 中
- 然后我们就可以把 `addi  %1, %1, %lo(symbol)` 删了，后面的 load/store 指令替换成 `lw %2, %lo(symbol)(%1)`，`sw %3, %lo(symbol)(%1)` 这种
### update
发现替换成 lw 会有绝对寻址的报错，需要用 auipc 来实现相对寻址，用 auipc 和 lw 相比，需要额外在 auipc 处插入一个 label，sw 处根据 label 定址，所以需要额外整一个 pcrel label manager    

