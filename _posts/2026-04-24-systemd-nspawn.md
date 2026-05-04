---
date: 2026-04-24 10:31:59
layout: post
title: 初步配置 ASAN 链接的 systemd 的 nspawn 容器
subtitle: 
description: >- 
    patchelf 上大分
image: >-
  /assets/img/uploads/jinan.jpg
optimized_image: >-
  /assets/img/uploads/jinan.jpg
category: hackedemic
tags:
  - systemd
  - nspawn
  - ASAN
  - LD_DEBUG
author: rosayxy
paginate: true
---

搞 Fuzz 的同学都知道，我们需要先能正常启动被插桩或者 hook 的程序，然后和它正常进行交互，这基本上是第一步。然而，对于一些测试目标，这个没那么好办到。

就像 systemd，它有一些特殊的环境的限制，如启动需要 PID 1，所以即使我们能正常的插桩并且编译它，也无法直接在宿主机上运行它来进行测试，而 docker 这种容器化的工具又没有 systemd，所以我们有以下两个需求：

1. 寻找合适的容器化方法来支持 systemctl/systemd
2. 能用我们编译的 systemd 来替换容器本身的 systemd，同时保证 systemd 的依赖是对的，并且兼容性没问题（启动的时候 systemd 能正常启动其他服务）

经过 jiegec 和 claude 的推荐，我们选择 systemd-nspawn 来做为启动的容器化工具，[Arch Wiki](https://wiki.archlinux.org/title/Systemd-nspawn) 下有如下描述：
> systemd-nspawn may be used to run a command or operating system in a light-weight namespace container. It is more powerful than chroot since it fully virtualizes the file system hierarchy, as well as the process tree, the various IPC subsystems and the host and domain name.

简单理解一下它在做啥，首先它有 chroot 的功能，可以把一个目录当做根目录来运行程序，这样就能保证我们在容器里运行的程序和宿主机的环境隔离了；此外它还提供了 namespace 的功能，可以把容器里的进程树、IPC、hostname 等等和宿主机隔离开来，这样就能保证容器里的程序和宿主机的环境完全隔离了。

然后 systemd-nspawn -b 意思是 boot，也就是在启动的时候会把容器里的 systemd 启动起来，从而满足我们的需求。

接下来是比较难的一步，如何替换容器本身的 systemd，同时保证我们启用的替换过的 systemd 能正常发挥功能？

直接从 systemd 项目中 meson install 的话，会有 d-bus daemon 等服务挂掉。这是因为 meson install 会替换 libsystemd.so.0 这个库为 ASAN 链接过的版本，然而 d-bus daemon 这些服务没有链接 ASAN，所以运行时会有如下问题：

```
dbus-daemon[115]: @dbus-daemon: symbol lookup error: /lib/x86_64-linux-gnu/libsystemd.so.0: undefined symbol: __asan_option_detect_stack_use_after_return
```

当然，这个问题的成因是这样的：我们用 ASAN 编译 systemd 的时候，用的是 Clang 编译器，它对于可执行文件，默认是静态链接的 ASAN，但是对于 libsystemd.so.0 来说，它没有链接 ASAN，所以会出现上述问题。

以及顺带用 GCC 做了个实验，写了一个程序和它依赖的动态库，分 1. 俩人都 ASAN 链接 2. 只有程序 ASAN 链接 3. 只有动态库 ASAN 链接；注意 GCC 默认会动态链接 ASAN 运行时

然后发现在只有动态库链接 ASAN 而程序没有链接 ASAN 的情况下才会有报错，belike

```
==9014==ASan runtime does not come first in initial library list; you should either link runtime to your application or manually preload it with LD_PRELOAD.
```

这是因为 ASAN 需要 track malloc 或者 free 这些函数的调用，所以需要被程序加载且第一个加载，而如上情景，程序依赖动态库，动态库再调用 ASAN 的函数/变量进行检查，此时程序和动态库使用同一个内存空间，如动态库访问一个堆上内存，ASAN 无法知道这个内存是否被程序申请或者释放过，所以无法进行 UAF 之类问题的 tracking，所以就有以上让程序第一个加载 ASAN 的要求了

好的我们继续往后看，有这个问题之后，我试图在 boot 的时候往 systemd-nspawn 里 preload GCC 的 ASAN 的动态库，**但是！** 我们其他 ASAN 动态链接的库，或者静态链接了 ASAN 的程序又会有一份 ASAN runtime，直接冲突报错....

但是因为这些服务都是 systemd 启动的，所以我一开始想让 systemd 启动其他如 systemd-logind, systemd-machined 这些服务的时候 preload ASAN 的动态库，但是这样需要改 systemd 的源码，感觉比较 dirty

然后和 jiegec 讨论了一波，感觉可能目前最好的方案还是回归到每个 CTFer（至少是 pwn 手）都会用到的工具--patchelf。

我们先让 meson build 把 target 安装到另一个路径，然后从 [systemd 源码](https://github.com/systemd/systemd/blob/6897562ea04c9a70622d5388c99e3e2ccf62e829/src/nspawn/nspawn.c#L3666) 里面找到 nspawn 启动 PID 1 systemd 的路径为 /usr/lib/systemd/systemd，然后替换它为我们自己编译的 ASAN 链接过的 binary，但是直接运行的话，会找不到 libsystemd-core-261.so 和 libsystemd-shared-261.so 这两个依赖，所以我们就直接 chroot 到 fake root 里，然后 patchelf /usr/lib/systemd/systemd 的 add-needed 加上同样是我们 meson build 的 libsystemd-core-261.so 和 libsystemd-shared-261.so 的路径，这样就能保证 systemd 启动的时候能找到这两个库了 ~

之后还有一个小坑点：如果 nspawn 的 base image 是 ubuntu 24.04 的话，我们换过的 systemd 版本太高，和其他 systemd-journald 这些需要启动的服务的组件不兼容，所以会报错如下

![alt_text](/assets/img/uploads/systemd-timeout.png)

所以我们把 nspawn 的 base image upgrade 到 ubuntu 26.04 就好一些了，目测就挂了 netplan-configure.service，不过这个服务不影响我们测试 systemd 的功能，所以就先不管了 ~

总的来说，虽然这个过程比较麻烦，但是我们成功地在 nspawn 里启动了我们自己编译的 ASAN 链接过的 systemd 了，感觉还是挺有成就感的，以及确实解决了问题 ~

我又回来补充了，现在是五一的第三天凌晨...在睡觉、摸鱼、给 NCO 的小朋友们出题和搓 ppt 的间隙磕一会盐....

大概就是，我继续研究了动态链接静态链接 ASAN 这一趴，大概就是我发现 /usr/lib/systemd/systemd 是静态链接的 ASAN，但是它依赖的我们手动链接的 libsystemd-core-261.so 和 libsystemd-shared-261.so 没有链接 ASAN，**但是运行起来没有任何问题！**

这是因为 GCC 默认会在可执行程序和动态库中都动态链接 ASan 运行时库，利用动态链接的特性保证只有一份 ASan 运行时库；Clang 默认不会在动态库中链接 ASan 运行时库，而是在可执行程序中静态链接 ASan 运行时库，这样也保证了只有一份 ASan 运行时库，可以参考 [Clang ASAN 文档](https://clang.llvm.org/docs/AddressSanitizer.html)

> Simply compile and link your program with -fsanitize=address flag. The AddressSanitizer run-time library should be linked to the final executable, so make sure to use clang (not ld) for the final link step. When linking shared libraries, the AddressSanitizer run-time is not linked, so -Wl,-z,defs may cause link errors (don’t use it with AddressSanitizer). 

这样的话，ASAN 的 global symbols 都在可执行程序中，如图所示

![alt_text](/assets/img/uploads/asan_binary.png)

这些 symbols 都是全局的

然后它依赖的动态库中有 ASAN 相关的 symbols，但是都是 undefined 如图

![alt_text](/assets/img/uploads/asan_lib.png)

就和我们一个正常的 binary 依赖一个 libc 中的函数（如动态链接情况下，依赖 libc 中的 printf 函数）的符号表是同一个情况

所以其实如果调用到 ASAN 的函数或者变量，动态库会去可执行程序中找这个符号的定义，然后就能正常调用了，所以就没有问题了 ~

已经到五一的第四天了，悲，明天还要去监考，希望能起来吧呜呜

最后还有一个有意思的小点：

遇到一个依赖的问题，可以理解为 systemd 依赖 libA 和 libB, libA 依赖 libB, ldd systemd 可以看到能正常找到依赖的 libA 和 libB 的路径，但是 ldd libA 依赖的 libB 找不到路径，但是 systemd 还是能正常运行，这是为什么呢？

遂写示例代码尝试查询，在仓库 https://github.com/Rosayxy/dependency-demo

可见存在以下输出

```
40807:	binding file /.../libA.so [0] to ./libB.so [0]: normal symbol `hello_from_B'
```
可以理解是如下原理：本质还是符号查询，而在运行时初始化的时候，系统会把 libA.so libB.so main 这些的符号表拼接在一起，像是 hello_from_B 这些符号都是全局的，所以 libA 说 “我需要 hello_from_B” 符号的地址，系统就会在 main 和 libA 和 libB 这些的总的大符号表里去找这个符号的定义，最终找到 libB 里有这个符号的定义，所以就能正常调用了 ~

所以还是一个 linker and loader 的问题了，感觉还是挺有意思的 ~
