---
date: 2025-08-10 10:21:59
layout: post
title: Defcon 2025 流水账
subtitle: 
description: >-
    getting 2nd with blue water
image: >-
  /assets/img/uploads/scores.png
optimized_image: >-
  /assets/img/uploads/scores.png
category: ctf
tags:
  - heap challenges
  - strace
  - justCTF 2025
  - FSOP
author: rosayxy
paginate: true
---

之前拜读过煜博和保证哥关于 Defcon 参赛经历的博客（[煜博的博客](https://brieflyx.me/2021/dc29-memo/)，[保证哥的博客](https://iromise.com/2021/08/11/DEF-CON-CTF-29-Final/)），现在终于我也可以写了吼吼！但是和两位学长不同，我是第一年 Defcon，并没有参与统筹和出谋划策，这篇更多是以一个 Defcon 萌新的视角简单写一下自己的参赛经历，记一个流水账 ~

总体情况：作为 blue water 的一员打的 Defcon Final，最终获得了第二名

## 赛前
### defcon quals
Defcon Quals 是在 PlaidCTF 之前，当时已经知道联队 blue water 可以进决赛了，但是 Redbud 还是想冲一下，看看能不能单独晋级（虽然很难）

因为当时是期中周，所以并没有多少人打，pwn 方向只有我一个人，主要是看了一个 reverse 的题，然后打了 liveCTF，感觉就是题目要不逆向量很大，要不就是需要额外学挺多东西，比如说 gcc exception table 结构之类的，在网上也很难找到一些 hands-on 的学习资源。好几道题都是还刚逆向完/理解大概怎么 hack 的时候 4 小时已经过去了，该切后一个题了

liveCTF 的讲解在 youtube 上有，见 [这里](https://www.youtube.com/@livectf/streams)

并且打完 Defcon Quals 第二天早上考操作系统期中，我甚至考前俩小时还在看队友在 callmerust 这个题上的进度，然后考试考的莫名的好，怀疑是不是把比赛的运气用在了考试上...

### preparations with blue water
5 月初 ouuan 问我要不要和 blue water 一起打 Defcon Final，并且问我要不要去线下。当时因为有传言保研机试要提前，怕有时间冲突，所以就决定线上参赛。过了几周，他把我拉进了 blue water 的 discord channel，我也就作为 Redbud 的一员加入了 blue water

之后几个周末，都是尽量在和 blue water 一起打比赛，并且 ENOWARS 9 是作为 Defcon 前的模拟来做的，主要是熟悉 Defcon 交流的时候队内使用的平台，打完 Defcon 后，感觉这个平台真是太不错了！

## 比赛情况
### 时间
比赛时间换算到北京时间如下

| Day  | Start Time | End Time |
|------|------------|----------|
| day 1 | 8 月 9 号 1 am | 8 月 9 号 8 am |
| day 2 | 8 月 10 号 1 am | 8 月 10 号 8 am |
| day 3 | 8 月 11 号 1 am | 8 月 11 号 3 am |

此外，比赛开始前有一个小时部署环境，比赛快结束的时候会放出 homework 题，来给大家在比赛间隙做

### 赛制
感觉和 [之前的](https://oooverflow.io/dc-ctf-2021-finals/) 大差不差，区别是多了 liveCTF 的得分，个人理解的 liveCTF 是两队各派一个人来 1v1 解同个题，谁先拿到 flag 就进下一轮，并且是双败淘汰制，时间和轮次安排如下

![alt_text](/assets/img/uploads/livectf.png)

打 liveCTF 的主力 sampriti 太强了，不愧是 man-machine hybrid（说的是自身能力和运用 AI 解题到了炉火纯青的程度哈哈哈）

![alt_text](/assets/img/uploads/hybrid.webp)

### 队员

队员大部分来自 Perfect Blue, Water Paddler, samsung, r00timentary, undef1ned，Tea Delivers (后文可能简称 TD)，和 Redbud 这几个战队

Redbud 这边主要是 ouuan, LZDQ, mori, papersnake 和我在看题，TD 的人里面看到了熟悉的保证哥，zTrix 和 f1yyy

### 物资
在宿舍备好了足量红牛，卡士酸奶，盒马家的迷你虎皮卷和山楂糕作为补给

## day 1

### 摩拳擦掌
放的第一个题是 `jukebox-echooo`，当时二进制手应该都在看同一道题，讨论空前热烈，并且很快找到了一个疑似后门的 `system` 函数

随着做题进度的推进和其他题目的放出，这道题的解题人员逐渐分成了两拨：一波是构造题目所需的 .wav 文件来触发后门，另一拨人是在进行 pwn 手的传统艺能：找内存漏洞

当时的我，UDP，KevinStevins 还有 hugeh0ge 都在找内存洞，更具体的话，因为逆向量比较大，所以主要是先逆完的 hugeh0ge 在把所有可能的漏洞点扔到 discord channel 里，其他几个人写 exp 来调试验证。搞了挺久之后大家达成共识：好像并没有内存漏洞....

这个题输入是一个音频文件，解码成文字用的是 [whisper](https://huggingface.co/docs/transformers/en/model_doc/whisper)，是一个 AI 的语音识别模型，看到师傅们遇到的一个问题是 LLM 会进行一些语句补全之类的推测，所以我们的音频可能会被补全成奇怪的内容，看到了队友 finetune 了音量，加噪声等一些方法来解决

然后 patch 主要是在一个 `filter.txt` 里面写东西，我的理解是滤波器的参数，指定滤波的类型（高通，低通，带通这种）和频率范围来滤波，可能可以比如说，把人耳能听到的频率范围给过滤掉，从而不会被 whisper 识别出来

这个题我没发现内存洞之后，就跟随 UDP 的脚步开始看下一个题--nilu，在我俩切换题目不久，被 Seraphin 做出来了

nilu 的话，静态链接去符号表，看着就头大，而且涉及到数据库相关操作

和 UDP 讨论了一下，感觉可以尝试一些数据库 fuzz 或者自动 Sql 注入的工具，但是当时已经凌晨 6 点半了，困的不行就先去睡了

### 进入主体
9点起床然后看了看新题，当时决定看一个 homework 题 `minicomputer`，原因是当时队友很多都下线休息去了，只有这个题还有其他少数几道还有人发消息讨论，事实证明这是一个很正确的选择，因为**只有这个题是堆题**，而且最后还算是做出了一点贡献

但是当时的我并不知道，接下来的两天我都会投入在该题目上....

#### 交互
这个题给了 `shredder`, `splinter`, `april`, `donatello`, `leonardo`, `michelangelo`, `raphael` 这几个二进制文件，它们交互的关系如下

![alt_text](/assets/img/uploads/minicomputer_workflow.png)

具体来说，shredder（管理器）进程负责启动并管理其他执行对应二进制文件的进程（raphael、april、michelangelo、leonardo）。在整个交互过程中，shredder 充当这些进程的 manager，通过 sigqueue 信号机制模拟类似 MMIO（内存映射I/O）的读写操作。
对应于 mmio，从架构上看，可以将 shredder 类比为主机控制器，而 raphael、april、michelangelo、leonardo 这四个进程类比为与之交互的外设。
用户输入的指令格式为 `r <address>`（读）和 `w <address> <value>`（写）。系统启动时会随机连接到四个进程中的一个（在本地环境下可以通过设置 TICK_TIME 环境变量来指定连接的目标进程）。
整个数据流向为：

1. 用户输入 → splinter（解析器）解析指令

2. splinter → shredder 传递解析后的指令

3. shredder 根据地址范围将指令路由到当前连接的目标进程

4. 目标进程根据地址的低2字节执行相应操作并返回结果

5. 结果通过 shredder → splinter → 用户的路径返回

此外，只能 patch 我们能连接到的进程中的一个，并且 `donatello` 读了 flag 存在内存中

因为 `april` 里面用了 AVX512 指令集，所以很多人电脑跑不起来，sampriti 给这个题在 AWS 上租了一个同版本的服务器

#### 还是流水账

北京时间的 9 号早上，我配了服务器上的 pwn 环境（像是装 pwntools，pwndbg, patch 掉 binary 里面的 sigalarm 这些），然后就开始用 claude 辅助逆向 `shredder` 的交互部分，当时 Seraphin 也在做这个题，我还在 struggling 去理解 `shredder` 里面的 sigqueue 相关交互是怎么 work 的时候，他已经把 `TICK_TIME` 和每次只能和一个特定进程交互这些研究清楚了，感觉好厉害

此时已经到中午一点了，就先下楼吃了个饭，吃完之后再看了一会到两点，然后又去睡了午觉，醒来已然4点

**此时 Seraphin 已发现 `leonardo` 里面有一个 UAF，`raphael` 有一个任意地址写**，我就开始写 UAF 的 exp，几经尝试，发现在跑 exp 时调试 `leonardo` 的方法如下

1. 先对于 exp.py，在想要调试的语句前加上 `pause()`
2. `python3 exp.py` 到了 pause 处，在另一个终端 `ps aux|grep leonardo` 找到 `leonardo` 的 pid，然后 `gdb -p <pid>` 进入调试
3. 因为它交互时会定期发 signal 轮询子进程的状态，所以需要设置 `handle SIG34 nostop` 和 `handle SIG35 nostop`

写了脚本模板的时候遇到一个问题，我输完 `w <addr> <value>` 试图给 `leonardo` 发 request 时，程序会 hang 住，在复现脚本时完全没出现也不该出现的问题。简单和对象讨论了一下，他建议查一下 `leonardo` 进程的状态，然后调试发现该进程在我发请求的前后都在 sleep，也就推测可能 `sigqueue` 没有发挥作用

然后就想是不是之前残留的运行 `leonardo` 进程之类的干扰了，就杀了一波之前残留的进程，但是还是会 hang 住，于是就在 discord 求助，看看有没有对 sigqueue 之前接触过的师傅解决，此时 f1yyy 说他来看看，加入本题战场

此时已六点多，和 f1yyy 同步了一波进度之后已近7点，感觉 “事已至此，先吃饭吧”，然后就和对象去新辰里楼下的一家韩餐吃了石锅拌饭和烤肉，别说还真不错的

回来8点多，试了一下发现不 hang 了（这个问题等会讲 xs），感觉很奇怪，就继续调试 heap 和 stack leak

过了一会，sugi 拿到了 UAF 的堆地址和 libc 地址的 leak，于是调试看堆布局，发现 UAF 的 leak 是 leak 的残存的 fd，libc 地址的 leak 则是利用 oob read 读出堆上原有的相对 libc 固定偏移的地址

这个时候已经晚上 10 点多了，f1yyy 说想打那个 `Raphael` 的任意地址写，但是可能不太熟悉新版本堆的攻击技巧，于是我就决定一起看看

这个题目的难点是无法读到堆上的内容，但是给了输出 pointer 的低4字节的方法，以及实现了一个 hashmap，在堆上分配的内存，有从 hashmap 查询或者输入数据的能力，通过低4字节 leak 堆地址的低位是简单的，但是 libc leak 低4字节有点难，我想到了 malloc 一个足够大的堆块的时候会使用 mmap 分配，得到的地址和 libc 偏移是固定的，所以由此，我们基本获得了**在一定爆破概率下的任意地址写**，此外 mmap 分配大堆块这个点后续也在 patch 的时候用到了，所以确实可以 mark 一下

首先这个题没有触发 IO 流的方法，甚至没有输出输入函数，我们不能打 FSOP，然后 Full Relro, libc 也是 Full Relro，所以只能用最传统的方法：劫持栈上返回地址

之后就缺少一个栈地址的 leak 了，一旦有它，我们劫持控制流就不成问题了，但是我们只能读那个堆上 hashmap 的内容，而无法读分配到的堆块的内容

大家讨论着都觉得一筹莫展，就不知不觉来到了第二天的正式比赛

另：day 1 结束的时候 我们是第二名

### day 2
省流：我还是在打 minicomputer 这个题，和前一天的不同点是参与了 patch 操作，对这个题不感兴趣的友友可以直接跳到 day 3

#### 一筹莫展的调试
之前脚本 pause 然后挂 gdb 的方法对调试 `leonardo` 的进程能 work，但是调试 `raphael` 的时候就会在一些奇怪地方 crash（比如说我们还没有输入的时候就会出现一个数组越界访问，index 是一个很大的数并且看上去像是堆地址右移若干位构成的）

f1yyy 给了以下（看上去有点玄学的）调试方法

![alt_text](/assets/img/uploads/minicomputer-debug.png)

但是我调试起来还是经常不 work，此时这个题可以 patch 的 4 个 binary 中还有 `april` 和 `michelangelo` 没有人看，`april` 的模拟器有点 dirty，我就先去逆向 `michelangelo` 找洞了

#### 一些感觉有意思的地方
1. 这个题 nop free 不 work，但是 day 2 感觉也没被其他队伍打，可能大家都觉得难？
2. 看到 f1yyy 保证哥和文雷学长他们也在熬夜奋战，莫名有点羡慕这种 "blue lotus for life" 的感觉，不知道我到了退役的年纪会不会也能这样

#### michelangelo
到了4点多，逆向找到了一个 oob read 和一个相对 mmap 地址的 oob read/write

当时有点累了，Seraphin 上线说来看看这个题，就把逆完的 binary 发到了频道上然后休息到了 5 点多

Seraphin 说那个 oob read 可能不 work，因为我们溢出的范围大概功能是一个 key-value 的 map，会 constantly 被其他进程改，然后看了以下 `leonardo`，果然是这样

六点多太困了就去睡觉了，睡到了 10 点多

#### 想不出小标题了，继续写流水账
起来的时候已经有大佬 voidmercy 在看题了，他很快的就搞出来一个 heap 完全体的 leak（膜拜ing），然后 day 2 的比赛时间，f1yyy 也通过那个堆上 hashmap leak 出了完整体的 libc 地址（继续膜拜ing）

然后一早上号发现服务器的 shrudder 又是一有输入就 hang，无法调试甚至连正常的运行都做不到，于是道心破碎

然后就和队友继续讨论 stack leak 的事情，但是并没有讨论出来啥，并且随着 voidmercy 的思路看了 leonardo 利用的可能性，感觉确实很难利用，遂摆
（具体情况是只能在 bk 为空的情况下对堆块进行写入，这就使得 tcache poisoning 很难（除非先进行 chunk faking 打一次 fastbin attack 把 fastbin 和 tcache 的 fd/bk 位置重叠），现在看来，可能也是可行的，但是会非常的 dirty）

看到保证哥在猛猛做另一个题，遂跑去问情况，得到的回答是“无法 patch”(没看题，继续疑惑中)。然后顺带说了一下这个 hang 的情况，保证的建议是起 docker 调试，感觉很合理

快到1点了，下楼吃午饭，在楼梯上遇到了焜焜，然后就一起吃饭（顺带进行了一些瓜的吃）

然后又困了，养精蓄锐准备冲刺晚上比赛

#### 对 hang 住情况的一个合理解释
发现有个队友的进程吃了 99.9% 的 cpu，所以怀疑 hang 住可能是没有足够的资源来 sigqueue 了就 hang 住了，就像[这里](https://pubs.opengroup.org/onlinepubs/000095399/functions/sigqueue.html) 说的 "The sigqueue() function can fail if the system has insufficient resources to queue the signal"

在我睡觉的时候有队友把这个进程终结了，然后我又可以正常不 hang 了

#### 调试（？
调试 `michelangelo` 遇到了和调 `raphael` 相同的问题，感觉无法征服，遂决定相信自己的逆向，并且简单确认了一下，不会出现之前的那个被其他进程的 signal 改数据的问题

#### stack leak finally
如图策略，感觉想起来很自然，自己也确实有往那个方向想（虽然是想的插到 tcache 链表）但是确实差一点功力，没想到

![alt_text](/assets/img/uploads/stack_leak.png)

#### further exploit

能 rop 了，但是有沙箱如图

```
$ seccomp-tools dump ./shredder
connected => 1
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x19 0xc000003e  if (A != ARCH_X86_64) goto 0027
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x17 0x00 0x40000000  if (A >= 0x40000000) goto 0027
 0004: 0x15 0x17 0x00 0x00000001  if (A == write) goto 0028
 0005: 0x15 0x16 0x00 0x00000000  if (A == read) goto 0028
 0006: 0x15 0x15 0x00 0x0000003c  if (A == exit) goto 0028
 0007: 0x15 0x14 0x00 0x000000e7  if (A == exit_group) goto 0028
 0008: 0x15 0x13 0x00 0x00000066  if (A == getuid) goto 0028
 0009: 0x15 0x12 0x00 0x00000027  if (A == getpid) goto 0028
 0010: 0x15 0x11 0x00 0x0000000d  if (A == rt_sigaction) goto 0028
 0011: 0x15 0x10 0x00 0x0000000f  if (A == rt_sigreturn) goto 0028
 0012: 0x15 0x0f 0x00 0x0000000c  if (A == brk) goto 0028
 0013: 0x15 0x0e 0x00 0x00000009  if (A == mmap) goto 0028
 0014: 0x15 0x0d 0x00 0x0000000b  if (A == munmap) goto 0028
 0015: 0x15 0x0c 0x00 0x00000019  if (A == mremap) goto 0028
 0016: 0x15 0x0b 0x00 0x000000db  if (A == restart_syscall) goto 0028
 0017: 0x15 0x0a 0x00 0x000000e6  if (A == clock_nanosleep) goto 0028
 0018: 0x15 0x02 0x00 0x00000081  if (A == rt_sigqueueinfo) goto 0021
 0019: 0x15 0x01 0x00 0x0000003e  if (A == kill) goto 0021
 0020: 0x06 0x00 0x00 0x00000000  return KILL
 0021: 0x20 0x00 0x00 0x00000010  A = args[0]
 0022: 0x15 0x00 0x04 0x00064cc0  if (A != 0x64cc0) goto 0027
 0023: 0x20 0x00 0x00 0x00000018  A = args[1]
 0024: 0x15 0x03 0x00 0x00000022  if (A == 0x22) goto 0028
 0025: 0x15 0x02 0x00 0x00000023  if (A == 0x23) goto 0028
 0026: 0x06 0x00 0x00 0x00000000  return KILL
 0027: 0x06 0x00 0x00 0x00000000  return KILL
 0028: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```
因为用到的 syscall 有限，所以猜测还是要和已经内存里有 flag 的 `donatello` 进程交互，所以就开始继续研究 sigqueue 怎么传参数

第二天的时候，大家发现我们 defense 的分并没有优势，于是开始检查各个题的 patch 情况

到了九点多，被 LZDQ 和其他队友发现，这个题还没有 patch 准备好（可能也是因为 day 2 正式比赛的时候没啥其他队伍攻击这个题），于是索性和 LZDQ 加入了 patch 的行列

先把 michelangelo 的越界 patch 没了，具体来说，他是计算访问 index 的时候是用的 `page_index * page_size + page_offset` 的方法，page_size 可以由我们设置，是 value & 0x7fff，把这个改小成了 0xfff

raphael 的 patch 是使得那个 hashmap 分配内存的时候，分配大内存来用 mmap 分配，这样我们从堆上 leak 值的方法就不能 work 了（同时如果其他队是用的 mmap 来 leak libc，mmap 的布局也会不同造成失败）

leonardo 的 patch 是在 UAF 后清零指针，用的是 e9patch

april 逆向的队友 szk3y 可以在一个 rwx 的 mmap 空间里面写 shellcode 但是没找到洞，这个交互机制是四个 binary 里面最复杂的，就感觉可以赌一把没人打它

#### get flag!
最后队友成功拿到本题 flag! 好耶！

其中有个有意思的 bug 是中途发现很奇怪的事情：在读写 shellcode `sub r15, r15 0x6654` 的时候，会莫名 sigkill，喊了刘大爷来 debug 然后发现被编码成了比正常汇编都要长的一份有点怪的东西

![alt_text](/assets/img/uploads/shellcode.png)

应该是原先的 x64 指令集不支持这种三操作数的写法，但是 [apx](https://www.intel.com/content/www/us/en/developer/articles/technical/advanced-performance-extensions-apx.html) 又有，所以就编码为了 apx 指令集，而硬件又不支持，就 crash 了

### day 3
只有两个小时

第一个小时主要是在修这个题的 patch，这个 patch 是提交一个可以 build 出 image 的环境：Dockerfile 和那几个 patch 过的文件

大家发现不对劲的地方：只要 Dockerfile 出现 COPY，哪怕是 copy 一样的 binary 都会被打回来，于是考虑权限问题，发现**应该只给 owner +x 的权限**，不给普通用户组，改正后就好了

#### april？
发现竟然有人打 april??

啊？

于是根据它的输入序列写脚本拿 flag，在最后一轮前写完脚本，但是因为过于匆忙，其中有一步是要把脚本前面加上一个轮询看 connection 为多少的一步，如果 connection 不为 4 就直接 return

加完之后，没注意到改了脚本中 process 的名字，导致 payload 发不出去，是非常低级的错误....

### scoreboard

我们第二

![alt_text](/assets/img/uploads/defcon_scoreboard.png)

### aftermath

打完爽睡到早上 11 点，吃完饭继续睡，然后刷手机到5点才下床 笑死

## 总结

还是很感谢这次打 Defcon 的机会，并且打的时候真的感觉到了 team spirit，大家在 discord 里面互相发 emoji，给 thumb-up 表情

希望明年也能进，如果能线下一起玩就更好了！