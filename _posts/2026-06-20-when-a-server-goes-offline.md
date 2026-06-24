---
date: 2026-06-21 10:29:59
layout: post
title: 纪实文学：今早我的主用 server 突然连不上了....
subtitle: 
description: >- 
    一点服务器管理的基础知识
image: >-
  /assets/img/uploads/moon.jpg
optimized_image: >-
  /assets/img/uploads/moon.jpg
category: half-finished
tags:
  - 运维
author: rosayxy
paginate: true
---

众所周知，我最近经常在组里的一个服务器上搞开发，今天早上，我发现 vscode 连不上它了，tailscale 也显示上一次这个服务器活动是在两个小时之前，于是我就开始 trouble shooting 的过程。

## 连接

同以太网有另一台服务器我们可访问，简称为 server B，那台突然连不上的的服务器叫 server A，我们尝试以 server B 做跳板连接上 server A，具有如下过程

首先在 server B 上利用 `sudo lldpcli show neighbors` 查看邻居设备信息，LLDP 是链路层的协议，是 Link Layer Discovery Protocol，即使不知道邻居设备的 ip，它也是可以正常工作的，然后我们查看到的信息基本如下

![alt_text](/assets/img/uploads/lldp.png)

这个 Mgmt address 是我们尝试找的 server A 的 ip 地址，但是这不能保证我们能正常连上它，因为它不一定是给我们用的（belike 给虚拟机用的 ip 地址、tailscale 的 ipv6 地址这样）

但是既然有这个邻居节点，就代表这个机器应该还活着

![alt_text](/assets/img/uploads/living.png)

然后我们尝试用 Forward Agent 以 server B 为跳板连接 server A，具体来说，直接在 server B 上执行 `ssh user@serverA.local` 会有 publicKey 的报错，这个 serverA.local 是 local hostname 的意思，然后这个 ssh 则是连接同一个以太网（？）的另一个机子的 local ip，详见 [这个 reddit 问题](https://www.reddit.com/r/linux4noobs/comments/17fvw0r/how_does_hostnamelocal_work/)

由于我本机环境是 windows，所以在管理员 powershell 上跑以下命令

```
Get-Service -Name ssh-agent | Set-Service -StartupType Manual
Start-Service ssh-agent
ssh-add keypath\id_ed25519
```

然后开个窗口跑以下命令

```
ssh -o ForwardAgent=yes user@serverB
```

如果上网搜的话，大部分帖子都会说要改 ssh config 文件加上 ForwardAgent=yes，但是就是 troubleshooting 一次的事情为什么要改配置文件，感觉对我这种脑子记不住事情的人非常不友好... thanks to jiegec，发现了不用改配置文件的方法

然后在该 ssh 起的窗口执行 `ssh user@serverA` 即可正常连接

## 为什么 vscode 连不上这个机子
因为被分配的 ipv4 地址不见了，wlo1 只有 ipv6 地址，悲

讨论可能是 dhcp server 给的 ipv4 地址过期了，又没分到新的，但是这个感觉可能性不大，因为显然 dhcp server 是工作在局域网之上的（或者说一个 dhcp server 管一个局域网的地址分配），然后我连 tsinghua-secure 的时候感觉没遇到过没有 ipv4 地址的情况....

btw 其实可以研究以下 dhcp server 的实现，感觉还是有些巧思，比如我这台服务器每次分到的地址都是同一个，有点神奇，那就列个 TODO 吧hhh

还有可能是 dhcp client 和 server 交互超时，所以就思考如何尝试重新 trigger dhcp client 进行一次 ipv4 地址分配请求，在这之前，先还是要确定 server A 的 dhcp client 是啥，所以经过一番搜索和思考，能看出来 dhcp client 是 NetworkManager，感觉好神奇，这个是 `ps aux` 再 `grep` 了一下，看没有常见的 dhclient 这些 NetworkManager 的后端，然后 `journalctl -f -u NetworkManager` 有以下输出

```
dhcp4 (eno2): state changed new lease, address=....
```

所以看上去就是用 NetworkManager 来做 dhcp client！

没想到之前闲来无事尝试用 ai 挖过洞的软件竟然能在这里遇到，好神奇

然后在想怎么重新触发 dhcp 分配呢？众所周知，当你连接上局域网的时候，该局域网内负责的 dhcp server 就会给你尝试分发一个 ipv4 地址，所以我们就打开 nmtui，断开 Tsinghua-Secure 的连接，然后再重新连接，就是重新申请一个 ipv4 地址了，之后就可以正常连接了

