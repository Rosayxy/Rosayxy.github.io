---
date: 2025-07-27 10:21:59
layout: post
title: 解决 pwbdbg gdb wrapper 在 wsl2 上启动过慢的问题
subtitle: 
description: >-
    血的教训：所有软件在 wsl 下安装都不应该装在 /mnt 目录下...
image: >-
  /assets/img/uploads/starrail_firefly.jpg
optimized_image: >-
  /assets/img/uploads/starrail_firefly.jpg
category: hackedemic
tags:
  - python profiling
  - pwndbg
author: rosayxy
paginate: true
---
在先后换到 alienware 的两台笔记本后，都遇到一个问题：直接启动 gdb 和用 pwntools 里面 `gdb.attach(process)` 的时候，pwndbg 启动都会很慢，大概启动一次需要将近一分钟，之前一直不觉得是个问题，因为大部分比赛的瓶颈并不是调试，而是思维跟不上，出现卡题，所以就一直将就着，但是这周末打京东的比赛的时候，确实有点被烦到了，就决定彻底解决一下这个问题

## profiling
pwndbg 自带 profiling 的功能，设置方法为 `export PWNDBG_PROFILE=1`，这是基于的 python 的 [cProfile](https://docs.python.org/3/library/profile.html)，然后它就会去记录每个功能的用时，跑出来的结果存在一个 pstat 文件中，可以用 [SnakeViz](https://jiffyclub.github.io/snakeviz/) 来可视化，得到如下结果

![alt_text](/assets/img/uploads/snakeviz.png)

可以看到，最耗时的是 importlib 的过程，搜索可知，python 的 import 主要是从 system path 里面找 modules 和做 name binding 的过程，所以比较**I/O 密集型**，而在 /mnt 和 linux 的原生目录之间通信是通过网络的，对于这种 I/O 密集型的操作来说就会很慢，**而这也成为了整个加载过程的瓶颈**

## solution
我们就需要把 pwndbg 装到 linux 目录下，这样就不用通过网络通信了，而整个需要我们去重新安装一遍 `pwndbg`，按照 [文档](https://pwndbg.re/pwndbg/latest/setup/) 上的方法，`curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb`，然后我们在 `.gdbinit` 里面把原本的 `source /mnt/somepath/gdbinit.py` 注释掉，否则相当于启动 pwndbg 的时候又在 gdbinit 里面 load 了一遍 pwndbg，注释掉就可以正常启动 `pwndbg` 命令了

## support for pwntools
我们另一个需求是跑 python 脚本的时候，用 pwntools 里面 `gdb.attach(process)` 的时候，**我们启动的是 pwndbg 而非原生的 gdb**

这个的实现在 pwntools 里面见 [这里](https://github.com/Gallopsled/pwntools/blob/32ba51e965643150a91e3f567579d99dae0ba38f/pwnlib/gdb.py#L755)

```py
# https://github.com/Gallopsled/pwntools/blob/32ba51e965643150a91e3f567579d99dae0ba38f/pwnlib/gdb.py#L755
    gdb = misc.which('pwntools-gdb') or misc.which('gdb')

    if not context.native:
        multiarch = misc.which('gdb-multiarch')
```
我们只需要把 `pwntools-gdb` 的软链接指向 pwndbg 的 gdbinit 文件就可以了，具体来说，执行以下命令

```bash
sudo ln -s /usr/local/bin/pwndbg /usr/local/bin/pwntools-gdb
```
其中 pwndbg 用 `curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb` 安装的默认位置就是 `/usr/local/bin/pwndbg`，可以用 `which pwndbg` 来查看

然后启动 pwntools，里面 gdb.attach 的时候就会通过 pwntools-gdb 找到我们的 pwndbg 然后启动，成果如下

![alt_text](/assets/img/uploads/pwntools_gdb.png)

注意，如果直接改 `.gdbinit` 里面 source 文件的位置的话，会遇到 `import pwndbg` 的 module not found error，这是因为它 pwndbg 除了 gdbinit 之前，还是加载了虚拟环境之类的，所以一上来就跑 `gdbinit` 会报错

## 结论
还是一开始就在 linux 目录下安装程序比较好

本文 credit to jiegec，我家的配环境大手子