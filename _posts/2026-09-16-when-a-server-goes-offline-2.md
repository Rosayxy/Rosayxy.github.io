---
date: 2026-06-21 10:29:59
layout: post
title: 纪实文学：今天下午，我的主用 server 突然连不上了 2.0
subtitle: 
description: >- 
    一点服务器管理的基础知识
image: >-
  /assets/img/uploads/moon.jpg
optimized_image: >-
  /assets/img/uploads/moon.jpg
category: misc
tags:
  - 运维
  - 源进源出
author: rosayxy
paginate: true
---

现象和 [这篇博客](./2026-06-20-when-a-server-goes-offline.md) 一致。大概就是我半夜 coding 到 1 点，上午在开会所以没用自己的电脑，下午想着回家调一调容器环境的问题就回家学习，然后发现主用 server 又连不上了...

唉，好久没有写博客了，已经将近 3 个月了，有点哈人。投稿的时候感觉每天都在补天TT，希望 11 月能投出去吧qaq

按照之前博客的 debug 方法，我一路从另一台服务器连上了该机器，但是发现该机器的 ipv4 地址是有的而且和之前一样，于是我很懵比，为什么会这样qaq

然后询问 jiegec，他表示可能是服务器校园网认证掉了，所以服务器到校园网这段就不再可用了。我 nmtui 看了一下 connection，然后发现确实有这个问题！服务器上校园网的密码不见了，然后我输入密码保存，发现能 curl 通外网，但是我本机还是连不上！

之后继续 `ip route show default`，结果如下

```
default via 10.3.16.1 dev eno2 metric 50
default via 183.xxx.xxx.1 dev wlo1 proto dhcp src 183.xxx.xxx.xxx metric 600
```

这说明服务器发送给我的消息，因为有线网（eno2）的 metric 更小所以就走了有线网（死去的网原知识在攻击我），所以我们发送 `curl baidu.com` 这样，它能连上，但是是连接的有线网，belike

```
my server <-> 有线网 <-> 网关 <-> baidu server
```

而它连接我们的时候如图

```
my server <-> 有线网 <-> my other server <-> 无线网 <-> my laptop
```

然后为什么我们从本机到 server 的 ssh 连不上呢？因为请求可以正常通过无线网到达 server，但是 server 的回显并不会走校园网，而是走了 eno2，而 ssh 是建立在 wlo1 之上的，所以就没有 response

解决方法：

一开始去问 D 老师，D 老师表示让我新建一个路由表再加表项啥的，感觉并不太合理。

解决方法也是很简单：执行了 `sudo nmcli connection modify "Tsinghua-Secure" ipv4.route-metric 10`，其中 "Tsinghua-Secure" 是 `nmcli connection show` 出来的 wlo1 的名字，讲人话就是 wifi 名；这个 10 是一个 metric 的值，需要比 eno2 的 metric 值小

然后重新用 nmtui deactivate Tsinghua-Secure connection 再 activate，然后看 `ip route show default` 就好了

以及为什么会出现这种，我感觉啥都没做但是为什么突然连不上的情况呢？应该源头是校园网里面什么东西发生了变化，导致 wifi 断了，然后重连的时候，原先的一些临时配置（比如 metric(?)）就没了