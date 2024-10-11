---
date: 2024-10-09 10:22:03
layout: post
title: RRVM 编译器优化-待定系数法降复杂度
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
  - coefficient solving
author: rosayxy
paginate: true
---
# 待定系数法降复杂度
注：这是在当时编译器比赛（全国大学生计算机系统能力大赛-编译系统设计赛）实现这个优化 pass 之前写的设计思路文档。**big credit to [Fuyuki](https://github.com/Fuyuky)**，对于当时公开测例中 *matmul 1,2,3*,*recursive call 1,2,3* 有非常好的效果，这个算法的灵感来自于 Fuyuki，当时听到的时候惊为天人（同时感谢 Fuyuki 大 gg 在实现的时候多次帮忙 debug qaq）        
对于一些特定的函数，我们可以用待定系数法来把运算复杂度降低到O(n) 然后对通项进行模式匹配，进一步降复杂度到 O(1)    
## 算法
```
float func(float data, int num) {
    if (num < 0) {
        return 0;
    }
    num=num-1;
    data = data + func(data, num);
    data = data - func(data, num);
    return data;
}

```
上述例子可以用如下算法降低复杂度     
我们先对函数条件进行一些限制：1. 只有两个参数（这个可以扩展），2. 函数只会递归调用自身     
1. 我们先确定递归间的 *index* ,即存在一个变量，可以根据它的值确定是第几层递归调用，该变量由以下特征判断：
   1. 决定递归结束（cfg 中较前的位置存在叶节点，该叶节点的判断条件依赖于该变量）=> 加强条件： 函数基本块 branch 只依赖于该语句     
   2. 同个递归调用周期，读取的值都是该变量的同个不变量，如 *index-1*,*index/2* 这类
2. 待定系数

$$
func(data,num)=[f1,f3](num)^T\cdot [data,1]
              =f1(num)\cdot data+g(num)
$$

我们只需要求出来 f1,g 的值即可,在当前条件下，可以进一步简化，考虑 g(num) 在某次迭代后为 0 的情况    
在每次递归调用函数自身的地方，我们都把表达式展开 belike（但是实际中端代码中会化成ssa的形式）:
$$
f1(num)\cdot data=data_now=data+f1(num-1)\cdot data-f1(num-1)\cdot (data+f1(num-1)\cdot data)
                          = data-f1(num-1)\cdot f1(num-1) \cdot data
$$
从而可得

$$
f1(num)=1-f1(num-1)\cdot f1(num-1)
$$

问题：怎么确定 g(num) 为0？   
> 发现 g(num), 看 g(num)=一个东西\*g(num-1),假设只有两个 return 在一个分支下是 g(num-1)\*一个东西，另一个分支下是0，则可以确定  
## 实现

白板上这一段
$$
foo = \sum (k(d_1,d_2,...d_n) \pi(xi^{d_i}))
$$
或者这一段
$$
foo=\sum w(idx_1,idx_2,...idx_n) \pi(xi^{ij})
$$
w 的某一项都是指 f1(num) 的具体值这样子，然后在具体的运算中，我们可以调用 calc_coef （更精确的描述是 ）来计算该具体值    
实现时，简化到双变量，一次的情况，相当于 k1(num)*data+k2(num)
calc_coef 函数签名 belike: 接收一个传所有 w 的 array,然后返回填了所有 w 值的该 array，且需要保证该函数在每个基本块中只调用一次        
### 实现位置
中端，放在 pure_check 之后   

## 遍历求解
我们需要把函数中遇到的每一个变量都给替换成 data, num, constant（int,float）, 某次递归返回值 的线性组合的形式   
具体来说，我们用一个 HashMap 存储变量到保存上述系数和对应运算的 AST (不能无脑数组保存因为无法应对除法等情况)，在另一个 HashMap 中存储递归返回值到该数组中对应项的 index 的映射
然后再是 dfs 基本块求解，在所有最后的返回的地方集中把递归返回值展开 然后进行后续的模式匹配    
如果有乘积项这种就直接 return 不做了
算完 AST 后 update: （可以先不用 AST 了 sad）
- 还需要做多源 bfs，具体如下：
  - def 特殊点：基本块内有递归 call 的点
  - def 特可达点：（特殊点可达）从源到该基本块（不包含）路径上有特殊点
  - 对于每一个特殊点，有如下可能：
    - 所有前驱都是特可达点，那么该点除去特殊点标记
    - 有若干个前驱不是特可达点，那么该点除去特殊点标记，所有非特可达点前驱标记为特殊点
    - 该点所有前驱都是非特可达点，那么该点标记为特殊点
  - bfs 停止条件：特殊点不变
- 然后在每一个现有的特殊点处做替换 开头先插一个 call_coef 的调用，把得到对应 f(index-1),g(index-1) 当作 a[0],a[1] load 出
- 我们接着 bfs ，维护一个 `HashMap<Temp,Vec<Instr>>` 对于每个变量，存在以下系数 tuple ：(k(index),b(index)) 
- 然后就去推得到返回值系数的指令集，然后中途遇到乘法/除法/取模/GEP/Alloc 且非常数的情况下（k(index)）非 0 就直接返回了 (todo 这一段再好好想想) 并且想一下没听懂的那段指令集插入位置（update 看下面）  
- 最后 把原函数改写为
```c
func(data,num){
    alloc a[2];
    call_coef(a);
    load %1,0(a[0]); // 如果可以求通项的话 就把这俩 load 换成求通项，然后把 call_coef 删了
    load %2,0(a[1]);
    return %1*data+%2;
}
```
- 上面的那个 指令集插入，其实更好的说法是指令集映射，具体来说：
  - 我们需要得到对于一个 idx 的 k_index,b_index，然后维护 HashMap<LlvmTemp,(Value,Value,Option<ModNum>)>,key 是原本的 LlvmTemp ，value 是 k_index,b_index 在我们映射完代码的表示
  - 在最开始，比如对于 data，num ，分别有如下指令
  ```
   li %1,1
   li %2,0 ---------> 我们有 insert into hashmap (data,(Temp(%1),Temp(%2),None))
    li %3,0
    mov %4,num ---------> 我们有 insert into hashmap (num,(Temp(%3),Temp(%4),None))
   ```
   - 之后如果有命令 `addi %3, data, num` 则我们转化为如下指令
   ```
    addi %5,%1,%3
    addi %6,%2,%4------------> 我们有 insert into hashmap (%3,(Temp(%5),Temp(%6),None))
   ```
   - 然后考虑mul,div 的情况，此时，我们需要除数对应 data 那项为0，乘法中有一项 对应 data 的系数为0 否则直接返回(可以用 is_zero 来判断)
     - 比如有 `mul %7, %1, %3` 则我们转化为如下指令(假设 Hashmap 中 %7->(Temp(%8),Temp(%9),None)), %1->(Temp(%1),Temp(%2),None),%3->(Temp(%3),Temp(%4),None) Temp(%3) 是0
     - ```
        mul %8,%1,%4
        mul %9,%2,%4    qaw
        ```
   - 然后还有那个取模的问题，如果模数是 imm 就直接干，否则由于我们之前纯函数的判断，可以知道一定是全局变量，这样的话，需要保证所有全局变量都有同样的对该变量取模（否则返回）
   - 最后是最重要的 函数递归的问题，就 belike
    ```
    复用传入的 a[2]
    call_coef(a);
    gep t1,a,4
    load %1,0(a[0]);
    gep t2,t1,4
    load %2,0(a[1]);
    ```
    插入到我们标记为特殊点的前面，此时 %1，%2 分别对应 f(recurse_index),g(recurse_index) 的值，然后就比如说有个位置是 %23=call func(data1,recurse_index) 则我们转化为如下指令(注意此时 data1 对应的hashmap[data1].1 应该是0)
    ```
    mul %33, %1, hashmap[data1].0
    mul %34, %2, hashmap[data1].0
    ```
    - 然后 insert hashmap(%23,(Temp(%33),Temp(%34),None))

## todo
已经实现完了俩参数的版本，现在拓展到多参数
- 框架改成 对于每个 Param 尝试每一个当成 index 求解，如果不行的话就尝试下一个
  - 需要满足的条件：1. 递归调用传参传的同一个值，并且该值和该参数有关系 2. 分支跳转和它有关 3. 分支跳转无 data 项
- 此外，尝试进行拓扑排序，然后按照拓扑排序后的顺序进行求解
- div 只对一个参数的情况，遇到 convert 就退出
- TODO 这一步挪到 gvn 之后做，用 global value 去判断有没有指令相同

## 模常数
注：认为对所有常数取模都立即生成指令，但是还要赋值 mod_value，is_actived 便于返回值判断   
要求取模的数是一个立即数才可以进行以下步骤    
- 加减乘：讨论两个多项式的情况：
  - 对同一个数取模->生成相加指令 is_actived 设置为 false
  - 对不同数取模->爆炸 （除非模1这种特殊情况）
  - 有一个多项式对某数取模：生成相加指令 is_actived 设置为 false
- Div : 除法
  - 除数是保存的模数： 正常生成指令
  - 其他情况：爆炸
- 左移右移，或且异或之类的：
  - 只要有模数就爆炸
- Rem
  - 模数大于保存的模数：如果 is_actived 则不变，否则爆炸
  - 模数等于保存的模数： is_actived 设置为 true
  - 模数小于保存的模数：爆炸
- Comp
  - 任意一个数有模数标签都爆炸
- jumpCond
  - 由于之前要求过 jumpCond 的判断数都是常数，所以这里不用考虑
- phi
  - 只有所有 source 都是模同一个数才行，is_actived := source[0].is_actived&&source[1].is_actived&&...&&source[n].is_actived
- call
  - 任何一个参数有 mod_num 标签都爆炸

最后检查所有返回值是否都是有mod_value，是 actived 且 mod_value 都是同一个值，如果是这样就正常返回，在 wrapper_func 加取模指令     