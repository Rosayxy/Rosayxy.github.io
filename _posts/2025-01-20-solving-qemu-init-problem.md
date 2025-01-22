---
date: 2025-01-20 10:29:05
layout: post
title: problem shooting not processed modprobe binfmt-0000 problem on cpio compilation
subtitle: 
description: >-
    modprobe binfmt-0000 cannot be processed, kmod busy with 50 threads for more than 5 seconds now
image: >-
  /assets/img/uploads/error.png
optimized_image: >-
  /assets/img/uploads/error.png
category: misc
tags:
  - cpio
  - kernel pwn problem shooting
author: rosayxy
paginate: true
---
最近复健 kernel pwn 的时候遇到了这个报错，浅浅记录一下现象和解决方法吧 ~      
### 现象
原先给的 rootfs.cpio 可以使得以下命令正常启动：
```
qemu-system-x86_64 \
  -kernel ./bzImage \
  -initrd ./rootfs1.cpio \
  -nographic \
  -monitor /dev/null \
  -append "console=ttyS0 kaslr oops=panic panic=1 quiet" \
  -no-reboot \
  -m 256M \
  -s
```
（在旧设备上）把该 rootfs.cpio 单独放到某个目录下，然后使用 `cpio -idmv <rootfs.cpio` 解压该 cpio 文件到该目录    
（在新设备上）把静态链接的 exp 直接放到了该目录下，然后用 `find .|cpio -o -H newc >../rootfs.cpio` 压缩到另一个 rootfs.cpio 文件，然后用该文件跑上述命令无法正常运行      
报错为 **"request_module: modprobe binfmt-0000 cannot be processed, kmod busy with 50 threads for more than 5 seconds now"** 从而导致 /init 运行失败    
### solution
不要把编译好的 exp 放到该目录（相对的）根目录下，放到比如 [path to directory]/usr/bin/ 目录下就好 ~     
此外还有一个观察，因为最近新换了机子，原先的机子上 kernel pwn 在编译 cpio 上没出问题，然后在 windows 系统下把原先的 cpio 文件解压到的目录拷贝到新机子的时候会有部分 soft link 拷贝失败的问题，这也是一个可能的成因（但是 rosa 可能一时半会不会换新设备了qaq）    

### attempts
1. 首先上 google 和 chatgpt 分别拷打了一波，其中看到主要是文件系统不完整的原因，和我们的问题不匹配
2. 从"原先的 rootfs.cpio 可用 新的 rootfs.cpio 不可用" 推测是压缩 cpio 该步骤的问题，而非 qemu-system 运行这步骤的环境问题，把新机子出现报错的 rootfs.cpio 拷到老机子上跑出现同款报错，从而验证了这一点     
3. 试图把老机子的 find 和 cpio 二进制和解压到的文件夹拷贝到新机子的时候发现了该*部分 soft link 拷贝失败的问题* 于是在新的机子上重新解压了 rootfs.cpio 然后用 `find .|cpio -o -H newc >../rootfs.cpio` 压缩可以正常运行
4. 然后发现把 exp 放到 [extracted dir]/ 下不可运行，于是想到换个位置放，塞到 [path to directory]/usr/bin/ 就行了     
