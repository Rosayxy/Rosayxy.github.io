---
date: 2025-07-03 10:21:56
layout: post
title: found sth interesting
subtitle: kAFL crashes when enabling Hyper-V on Windows 11 on Guest OS
description: >-
    感觉有点赛博灯泡doge
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

在 "Diary of a Reverse Engineer" discord 群里描述了一下现象，发现大概的原因是 qemu 版本太老了（机子是 ubuntu20.04 + kAFL/Nyx 的 patch），qemu 对 Hyper-V 还不够兼容，如果是比如说 kvm 兼容性不能满足，kvm 挂了的话，可能整个 host 就 crash 了   

具体证据是 [2022 年 Hyper-V 才被 qemu 加上支持](https://kvm-forum.qemu.org/2022/Hyper-V%202022.pdf)    
以及查看了一下 [commit messages](https://github.com/qemu/qemu/commits?author=vittyvk)，发现大部分 commit 都是 2022 年后才有的    

![alt_text](/assets/img/uploads/hyper-v-support.png)

后续可能是更新一下 qemu 版本看看支不支持（如果好了的话，可以考虑给 msFuzz 之类的提个 pr 说明一下）   
等回到学校之后调试 linux 真机（跑 msFuzz 的 linux 机子），以及先给 kAFL 提了个 [issue](https://github.com/IntelLabs/kafl.linux/issues/18)，想看看他们怎么说   

