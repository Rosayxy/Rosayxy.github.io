---
date: 2025-07-03 10:21:56
layout: post
title: found sth interesting
subtitle: kAFL crashes when enabling Hyper-V on Windows 11 on Guest OS
description: >-
    近日赛博灯泡
image: >-
  /assets/img/uploads/silver_wolf_gaming.jpg
optimized_image: >-
  /assets/img/uploads/silver_wolf_gaming.jpg
category: hackedemic
tags:
  - Hyper-V
  - kAFL
  - vbs
author: rosayxy
paginate: true
---
如题，用 msFuzz 在 Guest OS 为 Windows 11 上 fuzz 的时候，当我在 Guest OS 上启用 Hyper-V 时，会提示 “重启来生效”之类的   
然后 shut down Guest OS 之后重新以同样指令 launch qemu，则整个 Host OS 就会 crash 掉   
怀疑是 Guest OS 上 vbs 和 [kAFL/Nyx 魔改过的 linux kernel](https://github.com/IntelLabs/kafl.linux) 里面某个模块不兼容的问题，vbs 的作用是在启动机子的时候最底层套一个 Hyper-V，就像原本是 `linux(nyx-patched)->qemu->Guest Win11`   
现在是 `linux(nyx-patched)->qemu->Hyper-V->Guest Win11`  

感觉可能会有的问题是 Guest Win11 上的 fuzzing agent 会给 qemu（同样也是 patch 过的）发 HyperCall 来实现 Host 和 Guest OS 之间的通信，但是开启 vbs 后，hypercall 可能会被 Hyper-V 拦截掉，导致 qemu 无法正常工作

但是感觉即使这样，Host OS 也不应该 crash 掉 orz

后续可能是等回到学校之后调试 linux 真机（跑 msFuzz 的 linux 机子），以及先提了个 [issue](https://github.com/IntelLabs/kafl.linux/issues/18)，想看看他们怎么说   

