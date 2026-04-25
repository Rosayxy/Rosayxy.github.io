---
date: 2026-04-18 10:31:59
layout: post
title: 简述一次给历史悠久 linux 项目装依赖的经历
subtitle: 如何在不知道有哪些依赖项目的情况下正确安装
description: >-
    pkg-config, build-deps and all that jazz
image: >-
  /assets/img/uploads/jinan.jpg
optimized_image: >-
  /assets/img/uploads/jinan.jpg
category: hackedemic
tags:
  - linux builds
  - pkg-config
  - dpkg
  - ubuntu packaging
author: rosayxy
paginate: true
---

呼，最近忙似了，好久都没更博客但是攒了超多博客素材，这一周感觉有点闲下来了，就慢慢更吧

昨天在和 npy 一起自习的时候，我在配一个历史悠久的 linux 服务的环境，并且它没有显式的给出来 dependencies 有哪些（给了一个 packaging spec，但是是 dnf based，预期和我 deb based 的包不一致，此外没有 Dockerfile），然后在安装包的时候遇到了一个 polkit-agent-1 的问题就是系统提示缺少这个程序，然后我 google 了一下，安装了 gnome-polkit 包，但是感觉和 polkit-agent-1 这个程序还是没啥关系，正在疑惑的时候，npy 提醒我在 packages.ubuntu.com 上搜一下 polkit-agent-1.pc，我：不理解但照做.jpg，然后就有如下图

![alt_text](/assets/img/uploads/polkit.png)

过了一段时间，某人又提示我用 build-deps 来一键安装全部依赖，感觉好用的！

于是这两天就梳理了一下这些操作中包含哪些 linux 包管理的知识点，感觉还是挺有用的，记录一下。

## pkg-config

首先第一个问题：我们怎么能够从这个项目的文件中看出来，并且搜索 `polkit-agent-1.pc`？这个就需要我们看出来这个项目由 pkg-config 来管理了，由 configure.ac 这个文件可以看到其中的以下内容：

```bash
PKG_CHECK_MODULES(GLIB, [glib-2.0 >= 2.68])
AC_SUBST(GLIB_CFLAGS)
AC_SUBST(GLIB_LIBS)

PKG_CHECK_MODULES(GIO, [gio-unix-2.0 >= 2.50])
AC_SUBST(GIO_CFLAGS)
AC_SUBST(GIO_LIBS)

```

[PKG_CHECK_MODULES](https://autotools.info/pkgconfig/pkg_check_modules.html) 是一个宏，描述是 “The main interface between autoconf and pkg-config is the PKG_CHECK_MODULES macro, which provides a very basic and easy way to check for the presence of a given package in the system”。可见该项目用了 pkg-config 来管理依赖。而根据 [pkg-config guide](https://people.freedesktop.org/~dbn/pkg-config-guide.html) 的介绍，package 安装的 library 会有一个对应的 .pc 文件，来包含 pkg-config 的 metadata，从而我们可以假设，这个项目依赖的 polkit-agent-1 这个库应该会有一个 polkit-agent-1.pc 的文件来描述它的 metadata，从而在 packages.ubuntu.com 上搜索 polkit-agent-1.pc 就可以找到它对应的包了

## build-deps

通过刚才这个 pkg-config 不断查询的过程，我们就能知道这个项目有哪些库的依赖了

What's more，如果这个库在 packages.ubuntu.com 上有对应的包的话，我们就可以通过 `apt-get build-deps` 来一键安装这个库的依赖了，感觉好用的！

但是上述操作的前提是 sources.list 中包含了对应的 deb-src 的源，否则 apt-get build-deps 是无法找到对应的包的，所以需要在 /etc/apt/sources.list 或者 /etc/apt/sources.list.d/ubuntu.sources 中包含如下内容：

```
Types: deb-src
URIs: http://cn.archive.ubuntu.com/ubuntu/
Suites: noble noble-updates noble-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb-src
URIs: http://security.ubuntu.com/ubuntu
Suites: noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
```

