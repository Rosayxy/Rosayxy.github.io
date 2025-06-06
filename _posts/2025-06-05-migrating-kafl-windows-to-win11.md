---
date: 2025-06-05 10:21:56
layout: post
title: migrating msFuzz-kafl to Windows 11
subtitle: 
description: >-
    with the help of my awesome boyfriend
image: >-
  /assets/img/uploads/kafl_ui.png
optimized_image: >-
  /assets/img/uploads/kafl_ui.png
category: hackedemic
tags:
  - qemu-system
  - Windows 11
  - kafl
  - msFuzz
  - ansible
author: rosayxy
paginate: true
---

简单记一下 msFuzz-kafl 迁移到 win11 的时候，进行了哪些修改    
## build
build 一步的改动详见 [这篇博客](https://rosayxy.github.io/unattended-installation-of-windows-11-in-packer/)    

## register harness driver and agent
之后遇到的问题是 *import into libvirt* 一步中， vagrant up --no-provision 迟迟起不来，而且 qemu 的命令行极其复杂，很难在该基础上接 vnc 看输出    
大概长这样，非常哈人     
![alt_text](/assets/img/uploads/vagrantup-qemu-cmdline.png)

然后读了 kafl 的源码，发现它没用到 vagrant，而是直接起 qemu 的   
然后一通分析，发现我们只要把 harness driver 和 agent 拷贝进之前 build 的 windows image 并且注册成 service 就行了   
what's more，因为 kAFL 里面这一步拷贝和注册 service 也是用 ansible 配置的，所以我们只用 merge 之后部署的 ansible yml 到一开始 make build 用的 playbook.yml 里面就行了，非常方便！    
[初始的 playbook.yml](https://github.com/0dayResearchLab/kafl.targets/blob/master/templates/windows/playbook.yml)   
[注册服务的 yml](https://github.com/0dayResearchLab/kafl.targets/blob/master/windows_x86_64/setup_target.yml)    
[merge 之后的 playbook.yml](https://github.com/Rosayxy/kafl.targets.win11/blob/master/templates/windows/playbook.yml)

## setting args for kafl
改了 [kafl.yaml](https://github.com/Rosayxy/kafl.targets.win11/blob/master/windows_x86_64/kafl.yaml)   
改了 image 路径并且加了 qemu_extra 来从 UEFI 启动 windows    
### debugging
这步其实很难 debug... 首先是它 kafl 的 qemu 是魔改过的，直接用命令行跑它的命令会有报错且很难改，删了一堆参数后用本地的 qemu-system 跑，然后 qemu 会 crash，和对象讨论了一下，发现应该是 harness 会发专门的 kafl_hypercall 然后 qemu 不认识就挂了   

包括也没办法接 vnc 来看输出，因为 kafl 的 qemu 是通过 socket 来通信，所以 vnc 的消息会被发送给 fuzzer，而不会转发到我们这边   

所以只能通过之前注册 service 的时候，看 log 对不对来推测应该注册成功了，然后 `./run.sh` 发现没问题，就非常开心   

## links
相关的配置传到 github 上了，如果配置有问题请提 issue 或者发邮件!    
- https://github.com/Rosayxy/packer-win11-hcl 
- https://github.com/Rosayxy/msFuzz
- https://github.com/Rosayxy/kafl.targets.win11

## conclusion
嗯，总体来说就是这样，然后还有一个小点是当发现自己本地 vnc 没有输出的时候，可以先 `lsof` 看 qemu 打开的句柄，然后看 vscode 有没有 forward 该端口到本地的 vnc viewer    

然后调试总体来说，记一下 jiegec 所说，先按照原理推测可能的原因，然后结合 log，源码来排查问题，嗯，感觉自己确实配环境的经验不够，以后还要多积累，多想多学    

最后是运行 kafl 的截图，真的好帅啊哈哈，以及确实学到了很多，格外感谢 npy jiegec 教我配环境qaq     

![alt_text](/assets/img/uploads/kafl_ui.png)
![alt_text](/assets/img/uploads/kafl_output.png)
