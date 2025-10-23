---
date: 2025-10-21 10:21:59
layout: post
title: Setting up IDA MCP with VSCode agent mode on Windows 11
subtitle:
description: >-
    在 Win 11 上配置 IDA MCP
image: >-
  /assets/img/uploads/starrail_pond.jpg
optimized_image: >-
  /assets/img/uploads/starrail_pond.jpg
category: misc
tags:
  - IDA MCP
  - VSCode agent mode
author: rosayxy
paginate: true
---

上周末要打国内某比赛，比赛前在杰哥的帮助下在本人的 Win11 机子上配好了 IDA MCP 的环境，记录一下过程以备后续参考。

## config
简单讲一下 MCP server 的工作原理，[MCP](https://en.wikipedia.org/wiki/Model_Context_Protocol) 本身是一个协议，具体可以看那个 wiki 链接，在笔者的配置中，IDA MCP 作为 MCP server 运行，VSCode agent mode 作为 client 连接到这个 server

MCP server 的必要性在于，可以给大模型一些 domain-specific 的功能调用接口，从而让大模型可以调用这些接口来完成一些特定的任务（比如 LLM 本身拿到一个二进制，它肯定不知道怎么去执行对应的反编译任务的对不对）

所以在这个模型中，MCP client 的功能是，处理大模型的 tool call，通过 mcp 去调用 server 提供的函数

而 MCP server 的功能是，提供这些 domain-specific 的功能接口，并处理来自 client 的请求

## IDA mcp setup

参考 [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) 的 README 配置就行，大概分为如下几步

1. 用 `pip install https://github.com/mrexodia/ida-pro-mcp/archive/refs/heads/main.zip` 安装 ida-pro-mcp 包，此时，有个 `ida-pro-mcp.exe` 的可执行文件会被安装到 Python 的 Scripts 目录下，如在本人机子上，是这个目录: *C:\Users\<username>\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.13_<hash>\LocalCache\local-packages\Python313\Scripts*

2. 把上述 scripts 目录加入到系统的 PATH 环境变量中

3. `ida-pro-mcp --install`

## 使用

1. 启动 IDA Pro，打开一个二进制文件，在 13337 端口启动 MCP server:

![alt_text](/assets/img/uploads/ida-mcp.png)

2. powershell 跑 `uv run ida-pro-mcp --transport http://127.0.0.1:8744/sse`

3. VSCode -> Command Palette - > MCP: Add server，添加 server，type 是 http，url 是 `http://localhost:8744/sse`，这一步会在 `C:\Users\<username>\AppData\Roaming\Code\User\mcp.json` 生成一个配置文件，如下

```
{
	"servers": {
		"my-mcp-server-13371337": {
			"url": "http://localhost:8744/sse",
			"type": "sse"
		}
	},
	"inputs": []
}
```

4. 启动 VSCode agent mode，尝试 vibe reversing 就像下图

![alt_text](/assets/img/uploads/vibe_reversing.png)

## how to troubleshoot

1. 重启 VSCode 界面（重启解决一切.jpg）
2. 查看 VSCode 的 OUTPUTS 窗口，看 MCP 的日志输出是否正常，正常的话应该有类似于 "Discovered xx tools" 的字样

3. 查看 VSCode 的 configure tools 是否有来自 MCP 的 tools，如下图
    ![alt_text](/assets/img/uploads/configure_tools.png)
    ![alt_text](/assets/img/uploads/tools.png)

4. 多次尝试之间建议 new chat 开启新的 LLM 会话，否则 LLM 可能会重复上次的错误回答然后偷懒不调用工具

## acknowledgements
感谢杰哥对本博客的帮助 ~
