---
date: 2024-10-09 10:29:05
layout: post
title: RRVM 编译器优化-software pipelining
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
  - 龙书
  - 软件流水线
author: rosayxy
paginate: true
---
# rrvm-software pipelining
本 Post 更类似于对龙书软流水的摘抄和理解，Sysyc 在实现上采用的是硬流水的方法，本 Post 并无实现对应
## 必要性
对于循环指令，在循环展开的基础上用软流水来减少硬件流水线中 load 之后立即 alu 等情况，从而提高性能
## 龙书算法
- 算法目的：在循环展开/一次考虑多个循环的时候，调整不同循环中的起始间隔和一个循环中的指令间的间隔，来使得总体执行的指令数最少     
  ![alt_text](/assets/img/uploads/software_pipelining-1.jpg)

- 假设：**机器可以在同一个时钟周期内发出一个load,一个store，一个算数运算，一个分支运算**,而我们板子的情况将在后面讲到
### 算法
#### 模数资源预约
说明： 启动间隔为T，相对调度方案为S，对于每个运算，指定了该运算相对于它所处迭代的开始时刻的执行时间
假设一个机器的资源表示为R=[r1,r2,r3,....]，这里的r_i 表示的是比如说用i=1,2,3 对应的 r_i 来表述同一个时钟周期内可以执行的 load,store,alu,branch 数量，而显然，如果一个循环的单次迭代需要用到用到n_i个单元的第i种资源，比如说是会执行2条 load 指令，那么就对应用到2个单元的第一种资源。则一条流水线化的循环的平均启动间隔至少是max_i(n_i/r_i)个周期，如果 max_i(n_i/r_i)小于1就循环展开一下吧   
接下来有如下结论: 假设已知了启动间隔为T(我们易于求出来T的下限)，把n个迭代当成整体考虑，令 RT[t]=[0,0,...,1,0,0,..0，1]，其中设 RT[t][i]==1,i为指令的类型      
定义array RT_s,其中有 
$$
RT_s[i]=\sum_{{t|(t mod T==i)}} RT[t]
$$
则没有资源冲突的时候，RT_s[i]<=R for every i

#### 数据依赖
假设第i次迭代中的运算 n_2 必须在第 i-alpha 次迭代中的运算 n_1 执行至少d个时钟周期后才可以执行，则给依赖边 n_1->n_2 加上标号 <alpha,d>
则 (alpha*T)+S(n2)-S(n1)>=d (T 为之前说的启动时间的间隔)   

#### 简化-无环数据依赖图
已知：机器的资源表示 R=[r1,r2,...,rn]，数据依赖图G=(N,E)，其中每个节点表示一个指令，每条边如上面的数据依赖所定义   
1. 求出理论上的最小启动间隔T_0 (比较简单，套用前面的公式)
2. 对于T_0,对于按照优先级的拓扑顺序访问每个节点n,   
   我们先按照数据依赖的约束求出一个最小的 s 为该运算相对于它所处迭代的开始时刻的执行时间，然后先从s到s+T_0-1，判断是否满足模数资源预约中的不等式条件，如果可以就找到了解法，否则将T_0<=T_0+1 重复上述过程     

#### 有环数据依赖图调度
if 比如说有环：
(alpha1\*T)+S(n_2)-S(n_1)>=d1     
(alpha2\*T)+S(n_1)-S(n_2)>=d2   
then S(n_1)+d1-(alpha1\*T)<=S(n_2)<=S(n_1)-d2+(alpha2\*T)
考虑图的强连通分量，每个节点都可以从分量中其他节点到达，考虑对SCC中一个节点的调度：
存在一个从n_1到n_2的路径p，则有 
$$
S(n2)-S(n1)>=\sum_{e在p中}(d_e-(\alpha _e*T))
$$
可以得出以下结论：
- 沿着任意一个环，各边的 $\alpha$ 求和是正数
- 环上延时的总和除以环上迭代距离的总和得到启动间隔的下界
- 进而得到，不等号右侧必然小于等于0，对于节点位置的最强约束来自于**简单路径**（不含环的路径）

和无环数据依赖图调度相比有如下变化：
1. 对于数据依赖图中一个环c，
$$
    T_0>=max(\sum_{e in c}d_e/\sum_{e in c}\alpha _e) ---------------①
$$
所以要满足 ① 和无环数据依赖图的两个约束条件   
2. 一开始需要求出E'={e|e in E,alpha_e=0}，和无环数据依赖图相比，调度单位为SCC（强连通分量）   
所以算法整体 belike:
```
for (T=T_0,T_0+1,.....,所有 resources 都被调度完毕)：
    E* = AllPairsLongestPath(G,T);
    // 以带优先级的拓扑顺序排序G中的SCC C
    for SCC C in G:
        for n in C:
            s0(n)=max_{e=p->n in E* with p scheduled}(S(p)+d_e);
        first=使得 s0(n) 取最小值的n;
        s0=s0(first);
        for s in range(s0,s0+T):
            if(SccScheduled(RT,T,C,first,s)) break;
        if C 不能在 RT 中调度 
            break

其中的SccScheduled belike:
if not NodeScheduled:
    return false;
for E' 中各边的优先级的拓扑排序访问c中剩下的每一个n:
    S_l=max_{e=n'->n in E*,n' in c and n' scheduled}(S(n')+d_e-(alpha_e*T))
    S_u=min_{e=n'->n in E*,n' in c and n' scheduled}(S(n')-d_e+(alpha_e*T))
    for(s=S_l;s<=min(S_u,S_l+T-1);s++):
        if(NodeScheduled(RT',T,n,s)) break;
    if n 不能在RT'中调度 return false;
```

#### 模数变量扩展
如果一个变量的活跃范围在单个循环内，那么称该标量变量为可私有化的   
变量扩展把一个可私有化标量变量转化为一个数组，让循环的第i次迭代读写第i个元素，可以消除数据依赖图中的环   
if 一个寄存器生命周期为l时钟，启动间隔为T，则同一个时间点只有 $q=\left\lceil l/T\right\rceil$个变量是活跃的    
算法改进：   
1. 先把和可私有化变量的相关的依赖关系删了
2. 在1的基础上进行有环数据依赖图调度
3. 对于每个可私有化变量v，计算q_v;令 Q=max(q_v);
4. 生成经过软件流水线化过的循环中，分配给可私有化变量v的寄存器数目为 q_v'=(q_v if Q mod q_v==0 else Q)
**todo 考虑寄存器分配，e.g. caller save callee save 这步在寄存器分配之前先 precolored**
这一步会把稳定时候的代码大小增加到原先q倍

### 和实际应用的差别
- 我们板子的情况：
  - 单个周期内可以执行两条指令，并且有如下限制：
    - 最多一次内存访存
    - 最多一次跳转指令 (branch/jmp)
    - 最多一次乘/除
    - 最多两条加或者减   
    - 最多一条浮点数运算指令
    - 两个指令中都不访问 flags（CSR）// 应该用不到，，
  - 此外也需要考虑指令延时
    - load 普遍用时3个时钟周期
    - CSR 用时1个时钟周期
    - MUL 用3个时钟周期
    - DIV 是6~68时钟周期（Latency = 2 cycles + log2(dividend) - log2(divisor) + 1 cycle）

- 实现位置
  - 后端
  - 思考：之前的instr-schedule 实际上是个非常朴素的实现，望通过software-pipelining 实现真正的instr-schedule(不是 instr-struggle(逃))
- 附加
  - 通过上述的算法，我们可以知道循环起始间隔和单次循环中相邻指令的相差间隔，但是还有一个问题就是循环节在哪里。第一个循环的最后一条指令的上一个时钟周期前加上跳转的标签L，最后一个循环的第一条指令后的一个时钟周期处加上跳转指令 BL reg,L     
  - 具体一次考虑/展开多少个循环，书中没给明确的答案但是给的例子中都是4~5次，这个做一个超参吧   
  - 板子浮点数延时看 https://starfivetech.com/uploads/u74mc_core_complex_manual_21G1.pdf P267 