---
date: 2026-06-20 10:30:59
layout: post
title: branch predictor 实现之性能衡量
subtitle: 
description: >- 
    learning something new and a bit hardware these days ~
image: >-
  /assets/img/uploads/moon.jpg
optimized_image: >-
  /assets/img/uploads/moon.jpg
category: half-finished
tags:
  - branch prediction
  - hardware registers
author: rosayxy
paginate: true
---

嗯又是好久没更博客的一期...今年几乎变成月更了（悲），然后这两个月忙着科研、毕业、导师的校企合作项目，所以没咋学新东西（唯一还好的点是挖了一些漏洞，我现在的微信拍一拍已经是“漏洞屯屯鼠” 笑死），DEF CON 打了但是题目没复现，当时做的 Live CTF 也没啥好做法，唉。

然后这周大概是处于每个月都有的那几天不想科研的时间，也没有 LOL 看所以学点新东西，给自己一点即时满足，以后还是要多学习多发博客（flag up）！

最近在看分支预测相关的一些东西，特别是 branch predictor 逆向这一块，就有一个问题：
