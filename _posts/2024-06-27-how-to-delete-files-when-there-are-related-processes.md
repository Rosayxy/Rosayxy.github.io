---
date: 2024-6-27 21:22:03
layout: post
title: How to delete files in windows when there are related processes
subtitle: 记一次有自启动限制的删文件夹经历
description: >-
  大家安装东西的时候一定要思考装在哪个位置，，
image: >-
  /assets/img/uploads/cloud.jpg
optimized_image: >-
  /assets/img/uploads/qingdao.jpg
category: misc
tags:
  - misc
  - delete-files
author: rosayxy
paginate: true
---
# How to delete files in windows when there are related processes
## 前情提要
去打矩阵杯，有一个题目和通达OA的服务器 loader 有关，pwn 手在这种渗透赛上还是蛮坐牢的，当我开始基本没啥事干的时候是五点多，就寻思要不逆一下这个 loader去 kill time，然后，，一不注意就把这个server装在了 D 盘上，，昨天记得把这个server给删了，但是可能没删干净吧，，
## tl;dr
最好是能找到“总进程”先结束了， wsl2 里面用linux的 rm -rf * 删除，对于删不了的就在 windows 的任务管理器中把进程强制结束了 在用windows的正常界面删除
## trials
今天回到了你北京，凌晨0：50和好朋友聊了一下校赛的出题的事情，寻思着再逆向一会驱动就睡的来着，然后转眼看到D盘里面有一个通达 OA server 相关的 MYOA 文件夹，而且里面还有一堆文件，就顿时觉得不对   
想删了它但是发现有报错（？）就是有进程现在在使用它，所以还一时半会删不掉，，就比较离谱，而且在windows上用 ps 也无法简单看出哪几个进程是属于通达OA的。所以我直接的想法就是 把电脑重启了，结果发现这个是开机自启动（对于一个 server 来说也不能说是很不合理？），，就有点小寄   
于是把这个错误放进google搜了一下，发现有两种方法，第一种是 在windows的任务管理器中把进程强制结束，再把文件夹删了，第二种是用管理员权限运行命令行删除。     
直接试了第一种，发现大概有四五个相关的进程的样子，但是删了一个的话，剩下的多个还会自动启动，直到发现一个名字比较笼统叫啥啥server的进程删了才不会自动启动。接下来试了第二种，兜兜转转试了一堆命令发现还是没有起到终止进程的作用，或者有什么命令行和参数和实际提供参数不匹配blahblahblah的错误，于是果断换到 wsl2 里面尝试     
比较顺利，一开始删掉了仨文件夹，其他两个在这个啥server进程结束后也不会自启动了，删了就好，，     
小总结一下，首先就是，由于条件限制而不能直接在网上找到直接答案而需要用脑子解决的real world 问题，感觉还是有必要写在博客里面的 xs 。还有，虽然在这里看上去挺简单，但是 trial and error 其实挺多的ww   