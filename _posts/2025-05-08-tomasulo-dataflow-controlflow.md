---
date: 2025-05-08 10:21:55
layout: post
title: \[Unfinished\] A view of Tomasulo's algorithm
subtitle: from the perspective of (simulated) dataflow and control flow
description: >-
    analysis based on the assignment of the course "Computer Architecture" in Tsinghua University
    (2025 Spring)
image: >-
  /assets/img/uploads/cherry-blossom.jpg
optimized_image: >-
  /assets/img/uploads/cherry-blossom.jpg
category: half-finished
tags:
  - tomasulo algorithm
  - computer architecture
author: rosayxy
paginate: true
---

rosayxy 写计算机系统结构 Tomasulo 大作业的总体过程：
1. 这文档上时间标的啥呀，咋可能只用俩小时 debug    
2. 这函数在哪调的，找找找
3. 我这 store 咋不对啊
4. 这 pc 跑哪去了
（debug 了一波对了，然后加上了分支预测又出锅了）
5. 我这同一条指令咋执行了两次啊，不知道，不会，感到神奇（但是最终还是老老实实 debug 去了 笑死）

感觉确实理解 tomasulo 的整体流程需要一定时间，而且始终没有找到一个完整的图，告诉我整体的数据流和控制流是长啥样子的   
大部分 tomasulo 的介绍都比较原理向，比如说是分支预测，register renaming 是怎么做的，但是关于实现上的一些问题却讲的比较模糊，而这也给写 tomasulo 的友友们造成了一定的困难和超长的 debug 时间   
大部分流程图都是按照硬件原件的画法，告诉你哪个模块连到了哪里，而没有具体的指令和数据的流动关系，所以本博客希望可以梳理这一点 ~   

## Workflow
![alt_text](/assets/img/uploads/tomasulo-workflow.png)

## Simulated Control Flow
我们在这部分看 cpu 模拟的指令在各组件之间的流向    
首先，我们整体 cpu 模拟的架构分为前后端，前端是指令 fetch 和 decode 的部分，对应常规所说五级流水的 IF, ID 两步，后端是执行和写回的部分。    
前后端的交互为：
1. 前端给后端提供要 dispatch 的指令
2. 后端可以更新 pc 也就是让前端 jump 到新的地址，并且 flush 流水线   

所以就像基本的五级流水线一样，经过 IF 取指，ID 解码之后，一条指令被递交给了后端，好戏即将开始 ~     

### dispatch
这部分涉及到往**保留站**和 **ROB** 的写入   

**保留站**是和每个功能单元（execution unit）对应的，它是存储了若干条适配于该功能单元类型，经过了 ID 段但是没有经过 EXE 阶段的指令，等待被执行   
在 dispatch 的时候，如果看到了保留站有空位，就会把指令放到保留站里面，等待它所有寄存器就绪后发射执行，在发射执行的时候，就会把该指令从保留站中取出来    

**ROB** 参考 [这篇博客](https://jia.je/kb/hardware/ooo_cpu.html?h=tomasulo#rob-reorder-buffer)，是维护了当前正在执行的指令，它的“入” 和 “出” 的时间分别是 dispatch 和 commit 指令的时候       

后端拿到该指令的时候，先把指令插到 ROB 里面去，然后对于非 EXIT 指令，用 ROB 的索引来把指令插入到保留站里面去，为什么插入保留站的时候需要传入 ROB 的索引，等会会讲到   

#### 实现向！ROB 和保留站的写入
ROB 大概是如下的结构：
```c
struct ROBStatusBundle {
    // ALU section
    unsigned result;
    // BRU section
    bool mispredict, actualTaken;
    unsigned jumpTarget;
    bool ready;
    // LSU section
    bool cacheHit;
    bool exception;
};
struct Instruction {
    unsigned instruction;
    InstructionType type;
    unsigned pc;
    BranchPredictBundle predictBundle; // 这个没咋用到 笑死
}
struct ROBEntry {
    Instruction inst{};
    ROBStatusBundle state{};
    bool valid = false;
};
```
所以我们只用赋值 Instruction 和 ready 就可以了，ready 是标志某个指令是否可以立即 commit，我们对非 Exit 的指令都赋值为 false    

然后对于插入保留站可能有点复杂，因为这一步需要同时完成保留站中寄存器状态和值的读取，寄存器是否有前序指令依赖关系的判断，和保留站的赋值    
1. 寄存器状态  
    我们保留站里面需要维护寄存器的值，是否被唤醒，和它的 RobIndex，为什么需要维护 RobIndex 是因为我们有**前瞻执行**，既是指令在 commit 把值写回 regfile 之前就可以得到应该写回的值，而该值会广播给保留站来更新，所以我们用 RobIndex 来标志这个寄存器的值是来自于哪个指令的执行结果，方便广播的时候及时更新    
    然后这个的官方名称是 *Implicit Register Renaming*，可见 [杰哥的博客](https://jia.je/kb/hardware/ooo_cpu.html?h=tomasulo#rob-reorder-buffer)    
    以及对应的，regfile 里面也需要对每个寄存器维护一个 robIndex，来标志这个寄存器的值正在等待哪个 robEntry 的执行结果，方便在该保留站写入的时候直接进行查询，而不用去遍历 ROB     
    所以我们保留站和 regfile 里面，每个 Entry 结构分别如下 IssueSlot 和 RegisterFile 里面每个

> Fear is the little-death that brings total obliteration. I will face my fear. I will permit it to pass over me and through me.
