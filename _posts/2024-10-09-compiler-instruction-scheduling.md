---
date: 2024-10-09 10:20:03
layout: post
title: RRVM 编译器优化-指令调度
subtitle: 基于模拟硬件流水线的指令调度
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
  - instruction scheduling
  - software pipelining
  - hardware pipelining
  - viterbi
author: rosayxy
paginate: true
---
# instruction scheduling
注：这是在当时编译器比赛（全国大学生计算机系统能力大赛-编译系统设计赛）实现这个优化 pass 之前写的设计思路文档。**big credit to [Fuyuki](https://github.com/Fuyuky)**   
指令调度大家肯定都很熟悉，我们这里把这个排序过程转成一个优化问题，按照软流水/硬件流水线/降低寄存器压力（优先发射生命周期更早终止的寄存器）等指标设置估值函数，从而用一个保存多状态的动态规划算法解决（viterbi 算法）    
[项目仓库](https://github.com/rrvm-project/SysYc)，主要与其中 commit c42b63f 有关，在比赛过程中，设置惩罚函数为纯硬件流水线        
## 建数据依赖图
对于块中的指令，从后往前遍历，维护以下依赖关系：
- 同一个寄存器读写/写读（其中也包含 load/store/call 相关写读）
- load store call 特殊指令，实现操作 belike：
  - 维护一个 store/call 的 Option，一个 load 的 vector
  - 在倒序遍历的过程中，遇到一个 store/call 就向当前 load 的 vector 中都连上边，清空 load vector 然后赋值那个 Option ，遇到一个 load 就向当前的 store/call 连边，并且把load 加入 vector，把store/call 清空   
- 在这些之外，维护每个变量的活着的范围（大概就是这个意思）
## instr-schedule
算法总体思路：
对数据依赖图进行 bfs，以惩罚为指标（当前暂时先考虑使得寄存器压力最小（即是同一时间内，活跃变量数最大值尽可能的小））每走一步都维护当前最佳的k条路径和对应的依赖关系图（此时k为超参数）    
实现细节：每次考虑依赖图上入度为0的点，尝试把对应指令加入并且算出惩罚量，如果发现在前k条最佳路径里面，就把该路径对应的依赖图上的该点和出边给删了，继续向下递归   

## 惩罚函数
### register punishment
首先可以注意一下，不会出现 live_in->use->def->use 的情况，所以 use 一定是在 live_in 或者 def 后面
#### 维护的数据结构
for 每个在这个基本块中出现过的寄存器，维护以下指标：
- use 的数量
- is_live_in,is_live_out
- Option\<Def_id\>, update 这个不需要hh
#### 评价指标
选择尽可能多的结束变量生命周期的指令（def->惩罚+x use down to 0 ->惩罚-x）
在该加减相同的情况下，考虑以下点：
- 使得更多点的入度变成0的指令优先
- 寄存器生命周期更快结束的指令优先
- 后继中的节点对应指令，寄存器生命周期更快结束的指令优先

### pipeline punishment
因为现有 punishment 会改变指令顺序，可能降低程序并行能力，反而会导致部分测例上的性能损失，比较 emo     
我们根据 software pipelining，对指令顺序进行调整，从而讨好处理器    
#### 处理器情况
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
 - fadd,fsub,fmv 之类的是5个时钟周期，fdiv 还有一个特殊之处是 repeat-rate 意思是 我们还需要等多少个 周期冷却才可以再次执行相同的指令（9-36 latency 8-33 repeat rate）fle,feq,flt: 4个时钟周期
- flw/fld: 2个时钟周期，fsw/fsd: 4个时钟周期   
- fMv: 2个时钟周期，MvInt2Float/Int2Float: 2个时钟周期，Float2Int: 4个时钟周期

**进而推测我们处理器型号**：
- 一个 load/store 运算单元
- 一个单元 for mul/div
- 一个单元 for br/ret/call 之类的跳转指令
- 俩整数 unit
- 一个浮点 unit
#### 算法
利用动态规划，给我们的 punishment 函数加参，函数签名
```rs
fn punishment(
	dag: InstrDag,
	state: &State,
	instr_id: usize,
	my_reads: Vec<RiscvTemp>,
	my_writes: Vec<RiscvTemp>,
) -> i32
```
，**惩罚量是处理器时延的增量**
- DP 状态转移：
  - 之前的每个状态都保留的是以下结构
```rs
struct State {
	instrs: RiscvInstrSet,
	score: i32,
	indegs: HashMap<usize, usize>, // 把节点的 id 映射到入度
	liveliness_map: HashMap<RiscvTemp, Liveliness>,
	call_ids: Vec<usize>,
}
```
- 现在的状态结构
```rs
struct State {
	instrs: RiscvInstrSet,
	score: i32,
	indegs: HashMap<usize, usize>, // 把节点的 id 映射到入度
	liveliness_map: HashMap<RiscvTemp, Liveliness>,
	call_ids: Vec<usize>,
    slot_times:(usize,usize),
    slot_instrs:(RiscvInstr,RiscvInstr)
}
```
所以完全可能会有同一个 instrs 对应两个状态的情况，也认为是正常的       
对于每一个可调度指令，尝试把该指令往两个 slot 塞，得到新的 slot_times 和 slot_instrs 从而和其他参数一起得到新的 state   
## 参考：[杰哥算法](https://github.com/TrivialCompiler/TrivialCompiler/blob/master/src/passes/asm/scheduling.cpp)
```cpp
#include "scheduling.hpp"
#include <queue>
// virtual operand that represents condition register
const MachineOperand COND = MachineOperand{MachineOperand::State::PreColored, 0x40000000};

std::pair<std::vector<MachineOperand>, std::vector<MachineOperand>> get_def_use_scheduling(MachineInst *inst); // 正常写法

enum class CortexA72FUKind { Branch, Integer, IntegerMultiple, Load, Store };

// reference: Cortex-A72 software optimization guide
std::pair<u32, CortexA72FUKind> get_info(MachineInst *inst); // 返回时延和InstrKind

struct Node {
  MachineInst *inst;
  u32 priority;
  u32 latency;
  CortexA72FUKind kind;
  u32 temp;
  std::set<Node *> out_edges;
  std::set<Node *> in_edges;

  Node(MachineInst *inst) : inst(inst), priority(0) {
    auto [l, k] = get_info(inst);
    latency = l;
    kind = k;
  }
};

struct CortexA72FU {
  CortexA72FUKind kind;
  Node *inflight = nullptr;
  u32 complete_cycle = 0;
};

struct NodeCompare {
  bool operator()(Node *const &lhs, const Node *const &rhs) const {
    if (lhs->priority != rhs->priority) return lhs->priority > rhs->priority;
    if (lhs->latency != rhs->latency) return lhs->latency > rhs->latency;
    return false;
  }
};

void instruction_schedule(MachineFunc *f) {
  for (auto bb = f->bb.head; bb; bb = bb->next) {
    // create data dependence graph of instructions
    // instructions that read this register
    std::map<u32, std::vector<Node *>> read_insts;
    // instruction that writes this register
    std::map<u32, Node *> write_insts;
    // loads can be reordered, but not across store and call
    // instruction that might have side effect (store, call)
    Node *side_effect = nullptr;
    std::vector<Node *> load_insts;
    std::vector<Node *> nodes;

    // calculate data dependence graph
    for (auto inst = bb->insts.head; inst; inst = inst->next) {
      if (isa<MIComment>(inst)) {
        continue;
      }
      auto [def, use] = get_def_use_scheduling(inst);
      auto node = new Node(inst);
      nodes.push_back(node);
      for (auto &u : use) {
        if (u.is_reg()) {
          // add edges for read-after-write
          if (auto &w = write_insts[u.value]) {
            w->out_edges.insert(node);
            node->in_edges.insert(w);
          }
        }
      }

      for (auto &d : def) {
        if (d.is_reg()) {
          // add edges for write-after-read
          for (auto &r : read_insts[d.value]) {
            r->out_edges.insert(node);
            node->in_edges.insert(r);
          }
          // add edges for write-after-write
          if (auto &w = write_insts[d.value]) {
            w->out_edges.insert(node);
            node->in_edges.insert(w);
          }
        }
      }

      for (auto &u : use) {
        if (u.is_reg()) {
          // update read_insts
          read_insts[u.value].push_back(node);
        }
      }

      for (auto &d : def) {
        if (d.is_reg()) {
          // update read_insts and write_insts
          read_insts[d.value].clear();
          write_insts[d.value] = node;
        }
      }

      // don't schedule instructions with side effect
      if (isa<MIStore>(inst) || isa<MICall>(inst)) { // todo 把这个优化加了
        if (side_effect) {
          side_effect->out_edges.insert(node);
          node->in_edges.insert(side_effect);
        }
        for (auto &n : load_insts) {
          n->out_edges.insert(node);
          node->in_edges.insert(n);
        }
        load_insts.clear();
      } else if (isa<MILoad>(inst)) {
        if (side_effect) {
          side_effect->out_edges.insert(node);
          node->in_edges.insert(side_effect);
        }
        load_insts.push_back(node);
      }

      if (isa<MIStore>(inst) || isa<MICall>(inst)) {
        side_effect = node;
      }
      // should be put at the end of bb
      if (isa<MIBranch>(inst) || isa<MIJump>(inst) || isa<MIReturn>(inst)) {
        for (auto &n : nodes) {
          if (n != node) {
            n->out_edges.insert(node);
            node->in_edges.insert(n);
          }
        }
      }
    }

    // calculate priority
    // temp is out_degree in this part
    std::vector<Node *> vis;
    for (auto &n : nodes) {
      n->temp = n->out_edges.size();
      if (n->out_edges.empty()) {
        vis.push_back(n);
        n->priority = n->latency;
      }
    }
    while (!vis.empty()) { // dfs
      Node *n = vis.back();
      vis.pop_back();
      for (auto &t : n->in_edges) {
        t->priority = std::max(t->priority, t->latency + n->priority);
        t->temp--;
        if (t->temp == 0) {
          vis.push_back(t);
        }
      }
    }

    // functional units
    // see cortex a72 software optimisation
    CortexA72FU units[] = {
        {CortexA72FUKind::Branch},          {CortexA72FUKind::Integer}, {CortexA72FUKind::Integer},
        {CortexA72FUKind::IntegerMultiple}, {CortexA72FUKind::Load},    {CortexA72FUKind::Store},
    };
    u32 num_inflight = 0;

    // schedule
    // removes instructions
    bb->control_transfer_inst = nullptr;
    bb->insts.head = bb->insts.tail = nullptr;
    // ready list
    std::vector<Node *> ready;
    // temp is in_degree in this part
    for (auto &n : nodes) {
      n->temp = n->in_edges.size();
      if (n->in_edges.empty()) {
        ready.push_back(n);
      }
    }

    u32 cycle = 0;
    while (!ready.empty() || num_inflight > 0) {
      std::sort(ready.begin(), ready.end(), NodeCompare{});
      for (u32 i = 0; i < ready.size();) {
        auto inst = ready[i];
        auto kind = inst->kind;
        bool fired = false;
        for (auto &f : units) {
          if (f.kind == kind && f.inflight == nullptr) {
            // fire!
            bb->insts.insertAtEnd(inst->inst);
            num_inflight++;
            f.inflight = inst;
            f.complete_cycle = cycle + inst->latency;
            ready.erase(ready.begin() + i);
            fired = true;
            break;
          }
        }

        if (!fired) {
          i++;
        }
      }

      cycle++;
      for (auto &unit : units) {
        if (unit.complete_cycle == cycle && unit.inflight) {
          // finish
          // put nodes to ready
          for (auto &t : unit.inflight->out_edges) {
            t->temp--;
            if (t->temp == 0) {
              ready.push_back(t);
            }
          }
          unit.inflight = nullptr;
          num_inflight--;
        }
      }
    }
  }
}
```

## rrvm-算法
todo: 如果是小基本块的话，思考能不能用 A* 算法
- 在建 Instrdag 的时候，同时维护每个节点的 pred 和 succ
- 在建完图后，先手动跑一遍 dfs 算出每个节点离终点的最小时延（按杰哥算法来就行）
- 对每个新的 State belike: 
```rs
struct State {
	instrs: RiscvInstrSet,
	score: i32,
	indegs: HashMap<usize, usize>, // 把节点的 id 映射到入度
	liveliness_map: HashMap<RiscvTemp, Liveliness>,
	call_ids: Vec<usize>,
  units:Vec<UnitStatus>
}
```
- 我们的算法和杰哥算法相比有以下的不同点
  - 杰哥算法是贪心，每次挑选软件上最优的一个，如果可以发射的话就发射出去
  - 我们用 dp ，算惩罚的时候，直接用硬件流水算就行了hhh
    - 具体来说，我们考虑发射每个指令的过程

      - 当前准备发射的时间周期是上一个 state 的发射时间+1，每个 state 额外保存一个参数是发射时间
       
      - 运行完成时间是当前所有 alu 的 full_cycles 的最大值，然后我们去检测本指令需要用的 alu 是否空闲或者先前指令执行完毕，如果是的话，我们去直接更新该 alu 的 node 为本条指令并且更新 full_cycles，本 state 的发射时间即为上个 state 的发射时间+1

      - 否则等待该类型 alu 的指令执行完毕的最短用时，然后我们去以同样方法更新 node 和 full_cycles,但是此时的发射周期为 等待该类型 alu 的指令执行完毕的最短用时+上个 state 的发射时间

      - 特殊点：注意 FDiv 的技能冷却时间

      - 最后的惩罚量是[当前所有 alu 的 full_cycles 的最大值]的增量

  - 但是为了后续调参方便，同时对软流水对应的离结束的距离设置一个比重，最后加到惩罚里面去