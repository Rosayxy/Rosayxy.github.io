---
date: 2026-04-21 10:31:59
layout: post
title: 如何在 LLM 写错 python import 的时候找到正确的包
subtitle: 
description: >- 
    "简述一次给历史悠久 linux 项目装依赖的经历" 的姊妹篇
image: >-
  /assets/img/uploads/jinan.jpg
optimized_image: >-
  /assets/img/uploads/jinan.jpg
category: hackedemic
tags:
  - ROS
  - nav2 messsages
author: rosayxy
paginate: true
---

大概是前几天在做毕设的时候让 ai 搓交互脚本，然后它写了一个

```py
from opennav_docking_msgs.action import DockRobot
```
报错如下：

```
ImportError: No module named 'opennav_docking_msgs'
```

其实我之前也没有用 python 写过 ROS2 的交互，google 了一下 DockRobot，发现它在 humble 版本上确实是 opennav_docking_msgs 包里的，但是为什么 import 不成功呢？就猜测是 humble 和 jazzy 版本的包管理出现了变化，于是搜索 "DockRobot jazzy" 出现了这个链接：https://docs.ros.org/en/jazzy/p/nav2_msgs/action/DockRobot.html，从而可见是在 nav2_msgs 包里，改一下 import 就好了。

但是当时我直接把问题扔给了那个写出问题的 ai，belike：你的代码写错了，自己修一下，然后它的做法分为以下几步：

首先看没有 opennav_docking_msgs 这个包，用 `apt list --installed | grep docking` 确认一下这个包确实没有安装，然后用 `apt-cache search ros-jazzy-opennav` 搜索它认为这个包所在的 apt 包，发现没有结果

于是它就用了更聪明的办法：看目前 navigation2 的已有代码，有没有使用到 DockRobot 这个 action，如果使用了，那么它就会在那个文件里找到正确的 import 语句，直接复制过来就好了

然后找到了 `typedef nav2_msgs::action::DockRobot DockRobot;` 这个语句，就知道了正确的 import 语句应该是 `from nav2_msgs.action import DockRobot`，直接改过来就好了

所以说，我们需要善用搜索引擎，或者发挥智慧，从已有的代码里找到正确的 import 语句，来解决这个问题
