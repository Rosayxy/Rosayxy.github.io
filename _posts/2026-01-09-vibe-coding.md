---
date: 2025-12-29 10:31:59
layout: post
title: 配置 vibe coding 环境 - Claude Code + 国内某第三方 router
subtitle: 
description: >-
    配置纯 vibe coding 环境 - Claude Code + 国内某第三方 router
image: >-
  /assets/img/uploads/claude-code-cli.png
optimized_image: >-
  /assets/img/uploads/claude-code-cli.png
category: ctf
tags:
  - vibe coding
author: rosayxy
paginate: true
---

众所周知，本博客的主人 Rosa 要毕设了，俗话说的好，“天要下雨，人要毕设”， Rosa 也只能乖乖地接受这个事实了。而由于导师不是很接受在 aflnet 基础上开发（确实 aflnet 有点太古老了，而且也没太有人维护最近），所以需要进行将 aflnet 迁移/部分迁移到 aflplusplus 的大工程。进行了两天的手动迁移 + VScode agent mode 下用 gpt-5.1 vibe coding，感觉效率可以再提高一些，和 @Elsa Granger，@iromise 讨论后决定尝试用 codex，Claude Code 等 CLI 工具来进行迁移。

因为采用的是国内某第三方 router，所以无法使用 codex，遂选用 Claude Code。因为我们并不是使用的 Claude 的官方 API，所以需要进行一些 LLM Gateway 的配置。一开始是用的 [claude code router](https://github.com/musistudio/claude-code-router)，但是存在如 [issue 985](https://github.com/musistudio/claude-code-router/issues/985) 的参数报错并且没被修，所以换成了 [LiteLLM](https://docs.litellm.ai/docs/tutorials/claude_responses_api)，此外，LiteLLM 作为 Claude Code 的 Gateway 也是官方推荐的做法，见 [官方文档](https://code.claude.com/docs/en/llm-gateway#litellm-configuration)

需要进行一些配置，以下是配置过程记录，基本按照官方教程来就行。

## 安装 LiteLLM

```bash
pipx install 'litellm[proxy]'
```

为什么需要用 pipx install 呢？是因为 pip install 会报错全局安装的话，需要 `apt install python-xyz` 之类的，而如果 apt install 则找不到 `litellm[proxy]` 这个 package。

可以看看 [这里](https://stackoverflow.com/questions/78229687/what-is-the-difference-between-pipx-and-using-pip-install-inside-a-virtual-envir) pipx 和 pip install 的区别。

## 配置 LiteLLM
```
export LITELLM_MASTER_KEY="sk-1234"
```
这个是沿用的 LiteLLM 启 Docker 的设置，实际上也可以换成其他的 key。

仿照 “Using Multiple Models" 创建 config.yaml 文件

## 配置 Claude Code

```bash
export ANTHROPIC_BASE_URL="http://0.0.0.0:4000"
export ANTHROPIC_AUTH_TOKEN="$LITELLM_MASTER_KEY"
```

然后 `claude --model <model_name>` 就可以使用了。注意需要指定 model name，否则会有 claude code 像 proxy 请求它原生的模型（如 sonnet 4.5 或者 haiku 4.5 然后找不到的问题）

![alt_text](/assets/img/uploads/proxy-error.png)
