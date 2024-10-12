---
date: 2024-10-09 10:24:03
layout: post
title: RRVM 编译器优化-llvm gep 指令消除
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
  - llvm
author: rosayxy
paginate: true
---
# 中端到后端 GEP 消除
注：这是在当时编译器比赛（全国大学生计算机系统能力大赛-编译系统设计赛）实现这个优化 pass 之前写的设计思路文档。**big credit to [Fuyuki](https://github.com/Fuyuky)**   
目的是消除冗余的 GEP 指令
[项目仓库](https://github.com/rrvm-project/SysYc)，当时比赛最后一天下午本来想实现这个就下班，但是当时突发线上测试超时的情况，我们回退了仓库版本（但是优化基本都还是全的），所以这个 pass 没有实现，但是思路还是很有参考价值的    

## 思路
```
%1 = getelementptr i32, ptr @Ptr, i64 0
%2 = getelementptr i32, ptr @Ptr, i64 1
```

之后 %2 只在 store 的时候被读取，且 store_offset + ( %2 相对于 %1 的 offset) 在12位以内，就可以不用产生 %2 而是把 store 的 offset(%2) 改成 (offset + ( %2 相对于 %1 的 offset))(%1) 来访存    

从而减少了指令，而且可以减轻寄存器分配/指令调度的压力         
## 条件
- addi 算出地址，addi 立即数小于12位
- 读出该地址的指令只有 store
## 实现算法
对指令进行遍历
- 扫第一遍： store 指令当 offset_reg 
- 扫第二遍：这些 offset_reg 在 store 以外没被读过
- 扫第三遍：谁写的 offset_reg 如果是 addi 指令 imm+offset<4096 就可以消除
- 扫第四遍：替换