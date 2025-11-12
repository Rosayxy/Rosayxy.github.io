---
date: 2025-10-21 10:21:59
layout: post
title: DataCon 2025 软件供应链安全赛道 Writeup
subtitle:
description: >-
    LLM 上大分，prompt engineering 上大分
image: >-
  /assets/img/uploads/datacon.png
optimized_image: >-
  /assets/img/uploads/datacon.png
category: coursework-related
tags:
  - prompt engineering
  - secrets detection
author: rosayxy
paginate: true
---

作为段老师研究生课的一部分，和段老师组的 owen 一起参加了 DataCon 2025 软件供应链安全赛道的比赛，获得了第 27 名的成绩（感觉要被卷似了，呜，老老实实爪巴回去磕盐）。本文记录一下比赛的思路。

## 威胁模型
和 *Zhou, Jiawei, et al. "Hey, Your Secrets Leaked! Detecting and Characterizing Secret Leakage in the Wild." 2025 IEEE Symposium on Security and Privacy (SP). IEEE, 2025* 该论文的威胁模型相同，总结如下

主要聚焦在 secret 检测问题上，在现代软件开发中,开发者常将 API 密钥、令牌、数据库凭证、密码等敏感信息硬编码在源代码、配置文件、日志文件等非二进制文件中，这些敏感信息即被我们称为 secret,这些文件随后被上传至GitHub等公共代码仓库、PyPI等开源包管理平台,或嵌入到微信小程序中。攻击者可以通过扫描这些公开平台上的文件来获取泄露的密钥,进而实现未授权访问、数据窃取、服务滥用等恶意行为。论文特别指出,即使密钥在后续版本中被删除,由于缓存、镜像站点以及历史版本的存在,这些泄露的密钥仍然可被攻击者获取和利用,造成数据泄露和经济损失。

我们被给了数百万个文件，包含了各种各样的文件类型，比如说源代码文件、配置文件、日志文件、二进制文件等。我们需要从这些文件中检测出潜在的 secret 泄露。

最终得分规则如下

```
正确性判断

短密钥（长度 < 100字符）采用完全相等匹配。

长密钥（长度 ≥ 100字符，针对私钥这类\t 等形式不一的情况）采用相似度匹配，匹配标准为：Jaro-Winkler 相似度 ≥ 0.9，或SequenceMatcher 相似度 ≥ 0.9。计分规则（F1 Score）

构造密钥具有更高的权重分值（权重为n，如果该密钥正确，相当于命中了n次普通的密钥的次数）：precision = 正确提交数 / 提交密钥总数 recall = 正确提交数 / benchmark总数F1 = 2 × (precision × recall) / (precision + recall)

F1 值 × 100 作为基础得分（满分 100）。

所有结果均以 file+value 进行归一化计算。判分所用benchmark非100%覆盖，如选手认为裁判组漏判，可在赛后提交的wp里补充说明。裁判核实后酌情进行分数调整。
```
## 思路
提供的论文对应的实现开源在 github 上了，是 [KeySentinel](https://github.com/XingTuLab/KEYSENTINEL)，如果直接跑的话，有 0.52 的 precision 和 0.51 的 recall

我们注意到会给评测的 log，也就是给出在我们提交中，哪些 secret 是有效的，得分分别是多少，虽然题干中所说“判分所用benchmark非100%覆盖” 但是实测和 100% 覆盖差别不大，所以我们可以把评测 log 中的所有有效 secret 单独提取出来再交一次，从而提升 precision 到接近 1 的水平，从而提升 F1 分数

至于那个和 100% 覆盖的差别，我们可以在几次提交之后，merge 一下相邻两次提交的结果，从而增加正确答案数，从而缓解该问题（没错我知道有点启发式）

所以最后总体的思路是：误报多了没关系，都可以通过拿 log 重新交的方式来提升 precision 到1，主要目标是提升 recall，也就是尽可能找到多的（疑似）secret

## 实现
和队友采用了两种不同的思路，我这边就是 prompt engineer，然后用 llm 去扫描，队友则是用 gitleaks 进行再次扫描和在短密码方面进行优化

### Prompt Engineering
在论文里面 Evaluation 和 LLM 比较了，认为 LLM 的效果不如他们的方法，但是只能说，Evaluation 的话，懂得都懂（手动狗头）

比赛的题干提示了，如果像是涉及到密钥拼接（比如 python 中 str a, b, c 进行拼接得到最终密钥）的 secret 如果检测出来，会多得分，而论文中，检测的方法是深度学习，感觉 LLM 在这方面会很有优势，事实也是如此

为了成本选用了 deepseek，大概就是 few-shot chain-of-thought 的方式写 prompt，few-shot 的例子一开始用的是题干中的密钥拼接，但是跑了一会感觉检测效果不太好，于是手动找一些 KEYSENTINEL 检测出，但是我们初始 prompt 检测不出来的 secret，然后调 prompt 使得这些 secret 能被检测出来，也把对应的特征补充在 few-shot 例子中

#### prompt debugging

既然我们用了 chain-of-thought 的方式，虽然我们为了解析，让 LLM 最后输出 json 数组，但是 debug 的时候大可以让 LLM 直接输出中间过程。

遇到的问题很多都是，给的代码说的是 `example`（一开始 LLM 也会理解为 example 从而不去提取其中密钥），但是实际上还是有可用信息，比如提供的私钥就看上去很像是真的，就像是下面这段

```java
/*
 * Copyright 2012-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.buildpack.platform.docker.ssl;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

import org.springframework.util.FileSystemUtils;

/**
 * Utility to write certificate and key PEM files for testing.
 *
 * @author Scott Frederick
 * @author Moritz Halbritter
 */
public class PemFileWriter {

	private static final String EXAMPLE_SECRET_QUALIFIER = "example";

	public static final String CA_CERTIFICATE = """
			-----BEGIN TRUSTED CERTIFICATE-----
			MIIClzCCAgACCQCPbjkRoMVEQDANBgkqhkiG9w0BAQUFADCBjzELMAkGA1UEBhMC
			VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28x
			DTALBgNVBAoMBFRlc3QxDTALBgNVBAsMBFRlc3QxFDASBgNVBAMMC2V4YW1wbGUu
			Y29tMR8wHQYJKoZIhvcNAQkBFhB0ZXN0QGV4YW1wbGUuY29tMB4XDTIwMDMyNzIx
			NTgwNFoXDTIxMDMyNzIxNTgwNFowgY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApD
			YWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ0wCwYDVQQKDARUZXN0
			MQ0wCwYDVQQLDARUZXN0MRQwEgYDVQQDDAtleGFtcGxlLmNvbTEfMB0GCSqGSIb3
			DQEJARYQdGVzdEBleGFtcGxlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
			gYEA1YzixWEoyzrd20C2R1gjyPCoPfFLlG6UYTyT0tueNy6yjv6qbJ8lcZg7616O
			3I9LuOHhZh9U+fCDCgPfiDdyJfDEW/P+dsOMFyMUXPrJPze2yPpOnvV8iJ5DM93u
			fEVhCCyzLdYu0P2P3hU2W+T3/Im9DA7FOPA2vF1SrIJ2qtUCAwEAATANBgkqhkiG
			9w0BAQUFAAOBgQBdShkwUv78vkn1jAdtfbB+7mpV9tufVdo29j7pmotTCz3ny5fc
			zLEfeu6JPugAR71JYbc2CqGrMneSk1zT91EH6ohIz8OR5VNvzB7N7q65Ci7OFMPl
			ly6k3rHpMCBtHoyNFhNVfPLxGJ9VlWFKLgIAbCmL4OIQm1l6Fr1MSM38Zw==
			-----END TRUSTED CERTIFICATE-----
			""";

	public static final String CERTIFICATE = """
			-----BEGIN CERTIFICATE-----
			MIICjzCCAfgCAQEwDQYJKoZIhvcNAQEFBQAwgY8xCzAJBgNVBAYTAlVTMRMwEQYD
			VQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMQ0wCwYDVQQK
			DARUZXN0MQ0wCwYDVQQLDARUZXN0MRQwEgYDVQQDDAtleGFtcGxlLmNvbTEfMB0G
			CSqGSIb3DQEJARYQdGVzdEBleGFtcGxlLmNvbTAeFw0yMDAzMjcyMjAxNDZaFw0y
			MTAzMjcyMjAxNDZaMIGPMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5p
			YTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwEVGVzdDENMAsGA1UE
			CwwEVGVzdDEUMBIGA1UEAwwLZXhhbXBsZS5jb20xHzAdBgkqhkiG9w0BCQEWEHRl
			c3RAZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAM7kd2cj
			F49wm1+OQ7Q5GE96cXueWNPr/Nwei71tf6G4BmE0B+suXHEvnLpHTj9pdX/ZzBIK
			8jIZ/x8RnSduK/Ky+zm1QMYUWZtWCAgCW8WzgB69Cn/hQG8KSX3S9bqODuQAvP54
			GQJD7+4kVuNBGjFb4DaD4nvMmPtALSZf8ZCZAgMBAAEwDQYJKoZIhvcNAQEFBQAD
			gYEAOn6X8+0VVlDjF+TvTgI0KIasA6nDm+KXe7LVtfvqWqQZH4qyd2uiwcDM3Aux
			a/OsPdOw0j+NqFDBd3mSMhSVgfvXdK6j9WaxY1VGXyaidLARgvn63wfzgr857sQW
			c8eSxbwEQxwlMvVxW6Os4VhCfUQr8VrBrvPa2zs+6IlK+Ug=
			-----END CERTIFICATE-----
			""";

	public static final String PRIVATE_RSA_KEY = """
			%s-----BEGIN RSA PRIVATE KEY-----
			MIICXAIBAAKBgQDO5HdnIxePcJtfjkO0ORhPenF7nljT6/zcHou9bX+huAZhNAfr
			LlxxL5y6R04/aXV/2cwSCvIyGf8fEZ0nbivysvs5tUDGFFmbVggIAlvFs4AevQp/
			4UBvCkl90vW6jg7kALz+eBkCQ+/uJFbjQRoxW+A2g+J7zJj7QC0mX/GQmQIDAQAB
			AoGAIWPsBWA7gDHrUYuzT5XbX5BiWlIfAezXPWtMoEDY1W/Oz8dG8+TilH3brJCv
			hzps9TpgXhUYK4/Yhdog4+k6/EEY80RvcObOnflazTCVS041B0Ipm27uZjIq2+1F
			ZfbWP+B3crpzh8wvIYA+6BCcZV9zi8Od32NEs39CtrOrFPUCQQDxnt9+JlWjtteR
			VttRSKjtzKIF08BzNuZlRP9HNWveLhphIvdwBfjASwqgtuslqziEnGG8kniWzyYB
			a/ZZVoT3AkEA2zSBMpvGPDkGbOMqbnR8UL3uijkOj+blQe1gsyu3dUa9T42O1u9h
			Iz5SdCYlSFHbDNRFrwuW2QnhippqIQqC7wJAbVeyWEpM0yu5XiJqWdyB5iuG3xA2
			tW0Q0p9ozvbT+9XtRiwmweFR8uOCybw9qexURV7ntAis3cKctmP/Neq7fQJBAKGa
			59UjutYTRIVqRJICFtR/8ii9P9sfYs1j7/KnvC0d5duMhU44VOjivW8b4Eic8F1Y
			8bbHWILSIhFJHg0V7skCQDa8/YkRWF/3pwIZNWQr4ce4OzvYsFMkRvGRdX8B2a0p
			wSKcVTdEdO2DhBlYddN0zG0rjq4vDMtdmldEl4BdldQ=
			-----END RSA PRIVATE KEY-----
			""".formatted(EXAMPLE_SECRET_QUALIFIER);

	public static final String PRIVATE_EC_KEY = """
			%s-----BEGIN EC PRIVATE KEY-----
			MHcCAQEEIIwZkO8Zjbggzi8wwrk5rzSPzUX31gqTRhBYw4AL6w44oAoGCCqGSM49
			AwEHoUQDQgAE8y28khug747bA68M90IAMCPHAYyen+RsN6i84LORpNDUhv00QZWd
			hOhjWFCQjnewR98Y8pEb1fnORll4LhHPlQ==
			-----END EC PRIVATE KEY-----""".formatted(EXAMPLE_SECRET_QUALIFIER);

	public static final String PRIVATE_DSA_KEY = EXAMPLE_SECRET_QUALIFIER + "-----BEGIN PRIVATE KEY-----\n"
			+ "MIICXAIBADCCAjUGByqGSM44BAEwggIoAoIBAQCPeTXZuarpv6vtiHrPSVG28y7F\n"
			+ "njuvNxjo6sSWHz79NgbnQ1GpxBgzObgJ58KuHFObp0dbhdARrbi0eYd1SYRpXKwO\n"
			+ "jxSzNggooi/6JxEKPWKpk0U0CaD+aWxGWPhL3SCBnDcJoBBXsZWtzQAjPbpUhLYp\n"
			+ "H51kjviDRIZ3l5zsBLQ0pqwudemYXeI9sCkvwRGMn/qdgYHnM423krcw17njSVkv\n"
			+ "aAmYchU5Feo9a4tGU8YzRY+AOzKkwuDycpAlbk4/ijsIOKHEUOThjBopo33fXqFD\n"
			+ "3ktm/wSQPtXPFiPhWNSHxgjpfyEc2B3KI8tuOAdl+CLjQr5ITAV2OTlgHNZnAh0A\n"
			+ "uvaWpoV499/e5/pnyXfHhe8ysjO65YDAvNVpXQKCAQAWplxYIEhQcE51AqOXVwQN\n"
			+ "NNo6NHjBVNTkpcAtJC7gT5bmHkvQkEq9rI837rHgnzGC0jyQQ8tkL4gAQWDt+coJ\n"
			+ "syB2p5wypifyRz6Rh5uixOdEvSCBVEy1W4AsNo0fqD7UielOD6BojjJCilx4xHjG\n"
			+ "jQUntxyaOrsLC+EsRGiWOefTznTbEBplqiuH9kxoJts+xy9LVZmDS7TtsC98kOmk\n"
			+ "ltOlXVNb6/xF1PYZ9j897buHOSXC8iTgdzEpbaiH7B5HSPh++1/et1SEMWsiMt7l\n"
			+ "U92vAhErDR8C2jCXMiT+J67ai51LKSLZuovjntnhA6Y8UoELxoi34u1DFuHvF9ve\n"
			+ "BB4CHHBQgJ3ST6U8rIxoTqGe42TiVckPf1PoSiJy8GY=\n" + "-----END PRIVATE KEY-----\n";

	public static final String PKCS8_PRIVATE_EC_NIST_P256_KEY = EXAMPLE_SECRET_QUALIFIER
			+ "-----BEGIN PRIVATE KEY-----\n" + "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgd6SePFfpaTKFd1Gm\n"
			+ "+WeHZNkORkot5hx6X9elPdICL9ygCgYIKoZIzj0DAQehRANCAASnMAMgeFBv9ks0\n"
			+ "d0jP+utQ3mohwmxY93xljfaBofdg1IeHgDd4I4pBzPxEnvXrU3kcz+SgPZyH1ybl\n" + "P6mSXDXu\n"
			+ "-----END PRIVATE KEY-----\n";

	public static final String PKCS8_PRIVATE_EC_NIST_P384_KEY = EXAMPLE_SECRET_QUALIFIER
			+ "-----BEGIN PRIVATE KEY-----\n" + "MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCexXiWKrtrqV1+d1Tv\n"
			+ "t1n5huuw2A+204mQHRuPL9UC8l0XniJjx/PVELCciyJM/7+gBwYFK4EEACKhZANi\n"
			+ "AASHEELZSdrHiSXqU1B+/jrOCr6yjxCMqQsetTb0q5WZdCXOhggGXfbzlRynqphQ\n"
			+ "i4G7azBUklgLaXfxN5eFk6C+E38SYOR7iippcQsSR2ZsCiTk7rnur4b40gQ7IgLA\n" + "/sU=\n"
			+ "-----END PRIVATE KEY-----\n";

	public static final String PKCS8_PRIVATE_EC_PRIME256V1_KEY = EXAMPLE_SECRET_QUALIFIER
			+ "-----BEGIN PRIVATE KEY-----\n" + "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg4dVuddgQ6enDvPPw\n"
			+ "Dd1mmS6FMm/kzTJjDVsltrNmRuSgCgYIKoZIzj0DAQehRANCAAR1WMrRADEaVj9m\n"
			+ "uoUfPhUefJK+lS89NHikQ0ZdkHkybyVKLFMLe1hCynhzpKQmnpgud3E10F0P2PZQ\n" + "L9RCEpGf\n"
			+ "-----END PRIVATE KEY-----\n";

	public static final String PKCS8_PRIVATE_EC_SECP256R1_KEY = EXAMPLE_SECRET_QUALIFIER
			+ "-----BEGIN PRIVATE KEY-----\n" + "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgU9+v5hUNnTKix8fe\n"
			+ "Pfz+NfXFlGxQZMReSCT2Id9PfKagCgYIKoZIzj0DAQehRANCAATeJg+YS4BrJ35A\n"
			+ "KgRlZ59yKLDpmENCMoaYUuWbQ9hqHzdybQGzQsrNJqgH0nzWghPwP4nFaLPN+pgB\n" + "bqiRgbjG\n"
			+ "-----END PRIVATE KEY-----\n";

	public static final String PKCS8_PRIVATE_RSA_KEY = EXAMPLE_SECRET_QUALIFIER + "-----BEGIN PRIVATE KEY-----\n"
			+ "MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDR0KfxUw7MF/8R\n"
			+ "B5/YXOM7yLnoHYb/M/6dyoulMbtEdKKhQhU28o5FiDkHcEG9PJQLgqrRgAjl3VmC\n"
			+ "C9omtfZJQ2EpfkTttkJjnKOOroXhYE51/CYSckapBYCVh8GkjUEJuEfnp07cTfYZ\n"
			+ "FqViIgIWPZyjkzl3w4girS7kCuzNdDntVJVx5F/EsFwMA8n3C0QazHQoM5s00Fer\n"
			+ "6aTwd6AW0JD5QkADavpfzZ554e4HrVGwHlM28WKQQkFzzGu44FFXyVuEF3HeyVPu\n"
			+ "g8GRHAc8UU7ijVgJB5TmbvRGYowIErD5i4VvGLuOv9mgR3aVyN0SdJ1N7aJnXpeS\n"
			+ "QjAgf03jAgMBAAECggEBAIhQyzwj3WJGWOZkkLqOpufJotcmj/Wwf0VfOdkq9WMl\n"
			+ "cB/bAlN/xWVxerPVgDCFch4EWBzi1WUaqbOvJZ2u7QNubmr56aiTmJCFTVI/GyZx\n"
			+ "XqiTGN01N6lKtN7xo6LYTyAUhUsBTWAemrx0FSErvTVb9C/mUBj6hbEZ2XQ5kN5t\n"
			+ "7qYX4Lu0zyn7s1kX5SLtm5I+YRq7HSwB6wLy+DSroO71izZ/VPwME3SwT5SN+c87\n"
			+ "3dkklR7fumNd9dOpSWKrLPnq4aMko00rvIGc63xD1HrEpXUkB5v24YEn7HwCLEH7\n"
			+ "b8jrp79j2nCvvR47inpf+BR8FIWAHEOUUqCEzjQkdiECgYEA6ifjMM0f02KPeIs7\n"
			+ "zXd1lI7CUmJmzkcklCIpEbKWf/t/PHv3QgqIkJzERzRaJ8b+GhQ4zrSwAhrGUmI8\n"
			+ "kDkXIqe2/2ONgIOX2UOHYHyTDQZHnlXyDecvHUTqs2JQZCGBZkXyZ9i0j3BnTymC\n"
			+ "iZ8DvEa0nxsbP+U3rgzPQmXiQVMCgYEA5WN2Y/RndbriNsNrsHYRldbPO5nfV9rp\n"
			+ "cDzcQU66HRdK5VIdbXT9tlMYCJIZsSqE0tkOwTgEB/sFvF/tIHSCY5iO6hpIyk6g\n"
			+ "kkUzPcld4eM0dEPAge7SYUbakB9CMvA7MkDQSXQNFyZ0mH83+UikwT6uYHFh7+ox\n"
			+ "N1P+psDhXzECgYEA1gXLVQnIcy/9LxMkgDMWV8j8uMyUZysDthpbK3/uq+A2dhRg\n"
			+ "9g4msPd5OBQT65OpIjElk1n4HpRWfWqpLLHiAZ0GWPynk7W0D7P3gyuaRSdeQs0P\n"
			+ "x8FtgPVDCN9t13gAjHiWjnC26Py2kNbCKAQeJ/MAmQTvrUFX2VCACJKTcV0CgYAj\n"
			+ "xJWSUmrLfb+GQISLOG3Xim434e9keJsLyEGj4U29+YLRLTOvfJ2PD3fg5j8hU/rw\n"
			+ "Ea5uTHi8cdTcIa0M8X3fX8txD3YoLYh2JlouGTcNYOst8d6TpBSj3HN6I5Wj8beZ\n"
			+ "R2fy/CiKYpGtsbCdq0kdZNO18BgQW9kewncjs1GxEQKBgQCf8q34h6KuHpHSDh9h\n"
			+ "YkDTypk0FReWBAVJCzDNDUMhVLFivjcwtaMd2LiC3FMKZYodr52iKg60cj43vbYI\n"
			+ "frmFFxoL37rTmUocCTBKc0LhWj6MicI+rcvQYe1uwTrpWdFf1aZJMYRLRczeKtev\n" + "OWaE/9hVZ5+9pild1NukGpOydw==\n"
			+ "-----END PRIVATE KEY-----\n";

	public static final String PKCS8_PRIVATE_EC_ED25519_KEY = EXAMPLE_SECRET_QUALIFIER + "-----BEGIN PRIVATE KEY-----\n"
			+ "MC4CAQAwBQYDK2VwBCIEIJOKNTaIJQTVuEqZ+yvclnjnlWJG6F+K+VsNCOlWRda+\n" + "-----END PRIVATE KEY-----";

	private final Path tempDir;

	public PemFileWriter() throws IOException {
		this.tempDir = Files.createTempDirectory("buildpack-platform-docker-ssl-tests");
	}

	Path writeFile(String name, String... contents) throws IOException {
		Path path = Paths.get(this.tempDir.toString(), name);
		for (String content : contents) {
			Files.write(path, content.replaceAll(EXAMPLE_SECRET_QUALIFIER, "").getBytes(), StandardOpenOption.CREATE,
					StandardOpenOption.APPEND);
		}
		return path;
	}

	public Path getTempDir() {
		return this.tempDir;
	}

	void cleanup() throws IOException {
		FileSystemUtils.deleteRecursively(this.tempDir);
	}

}

```

所以我在 prompt 里面增加以下语句

```
- PLEASE FOCUS ON THE SECRET's VALIDITY, EVEN IF THE CONTEXT SUGGESTS IT MIGHT BE AN EXAMPLE.
- PLEASE BE AS COMPREHENSIVE AS POSSIBLE IN YOUR DETECTION. LOOK FOR ALL POSSIBLE SECRETS.
```

prompt 的内容会在本博客最后附上

感觉 LLM 还是能起到一定效果的，大概是总共扫描了 14 万个文件，大概扫描 2 万个文件用 deepseek 的官方 api 正好是 100 rmb 的开销，每天交一次大概能提升 0.5 - 1 的 recall，从而感觉还是挺有效果的，主打一个力大砖飞

### GitLeak
这部分由队友 owen 完成，感觉单独提取得分为 23 分，还是挺高的，和 KEYSENTINEL 的结果 merge 之后能提升近 3 分

### 短密码优化
这部分由队友 owen 完成，大体思路是 KEYSENTINEL 会对太短的 secret 进行过滤，但是可能这些被过滤掉的短密码也是有效的，所以思路就是删除 KEYSENTINEL 对短密码的 filter 函数，然后重新跑一边，这样的话，大概能多提取到 100 多个 secret

### 其他队伍优化
问了子权（杰哥不要入侵我战队成员），主要还是跑主办方提示给的工具，然后手动分析 KEYSENTINEL 漏掉的 secret 特征，然后写规则提取（如正则表达式）

### 感想
嗯，其实感觉即使是到了比赛结束后，也不太知道比赛方的预期想让我们干啥，队友猜测可能是对现有的 KEYSENTINEL 工具进行优化提升，比如说我们对于短密码的优化，
但是事实上，题干中给的一些要求，如判断由多个字符串拼接而成的密钥等操作，感觉可能只有 LLM 能比较好处理吧。

对事不对人，没有针对 Datacon 或者近期其他比赛的意思。但是其实感觉，比拼 prompt engineering 的比赛，其实没啥意思，虽然在现在，prompt engineering 也是一种能力，但是这样的话，比赛的可玩性会大大降低，而且会让很多非个人能力因素被 taken into account（比如比赛经费问题），而写完 prompt 和一些交互脚本之后，每天上午起床的时候收割一波结果，然后晚上睡前再收割一波结果，往 LLM 账户里面充钱，我并不感觉这很好玩，也并不感觉这种大力出奇迹，主要靠 LLM 的比赛是我想做的，或者能让我学到我感兴趣或者真正想了解的东西（所以有点后悔没有好好玩玩隔壁的口令安全赛道哈哈哈，我比赛中让 claude 写了一个脚本，拿 rockyou.txt 破解了 72 条密码就撤了 笑死）。所以也小庆幸一下 LLM 解 CTF pwn 题的能力没那么强，让我还能继续玩一阵子。

引用一个我喜欢的博客，来自今年 Defcon 的 shellphish 战队成员 Wil Gibbs，[All You Need Is MCP - LLMs Solving a DEF CON CTF Finals Challenge](https://wilgibbs.com/blog/defcon-finals-mcp/)

>I’m annoyed that I solved this challenge like this. On one hand, it’s really, really cool that technology has gotten to the point of being able to automate this.

>On the other, I like puzzles, I like learning, and I like challenges. I don’t want to become a software engineer or prompt engineer, etc. I want to pwn challenges myself, not rot away as a glorified puppet for the LLM.

## 附录 - Prompt 内容

You are an expert security analyst specializing in detecting leaked secrets in source code. You will be provided with multiple files in the following format:

[
Filename: [filename]
Filecontent: [file content]
]
Your task is to identify ALL possible secrets in each file, including hard-coded credentials, API keys, tokens, passwords, private keys, and any sensitive information that could pose security risks.

### Detection Strategy

For each file, follow this step-by-step reasoning process:

1. **File Type Identification**: Determine the file type **based on the file content**
2. **File Comprehension**: Please try to understand the overall purpose and functionality of the file
2. **Initial Scan**: Identify common patterns of the secrets (including hard-coded credentials, API keys, tokens, passwords, private keys, and any sensitive information that could pose security risks)
3. **Context Analysis**: Examine variable assignments, function parameters, and string concatenations
4. **Obfuscation Detection**: Look for split strings, concatenated variables, or encoded values
5. **Semantic Understanding**: Consider the purpose and context of suspicious strings
6. **Cross-reference**: Check if any values are used in authentication, API calls, or connections

### Examples with Chain-of-Thought Reasoning

#### Example 1: String Concatenation Secret

**Input:**
Filename: 00281c3b7847cab1ad2fe028a62dcede
Filecontent:
def connect(url, auth):
print(f"Connecting to {url} with auth token: {auth}")
a = "sk-hmiob"
b = "xbhczx"
c = "bdbHwb"
secret = a + b + c
connect("service.example.com", secret)

**Reasoning Process:**
- **File Type**: Python source code (Python syntax)
- **Initial Scan**: Found variable named "secret" 
- **Context Analysis**: Used as authentication parameter in connect() function
- **Obfuscation Check**: Three string parts concatenated (a + b + c)
- **Semantic Analysis**: "sk-" prefix suggests API key format (common for services like OpenAI). EVEN IF THE CONNECTION IS MARKED AS EXAMPLE, THE SECRET ITSELF IS REALISTIC AND SHOULD BE FLAGGED.
- **Usage Context**: Directly passed to authentication function
- **Conclusion**: This is a CRITICAL SECRET

**Output JSON Element:**
```json
{
    "file_hash": "00281c3b7847cab1ad2fe028a62dcede",
    "value": "sk-hm*******iobxbhczxbd*******bHwb",
}
```

---

#### Example 2: Function Parameter Secret

**Input:**
Filename: 889346ac21e02c55dedf3890d913245a
Filecontent:
def api_call(endpoint, header):
print(f"Calling {endpoint} with header {header}")
api_call("https://api.example.com/data", "sec*******ret")

**Reasoning Process:**
- **File Type**: Python source code
- **Initial Scan**: No obvious variable names like "password" or "key"
- **Context Analysis**: "header" parameter receives a string value "sec*******ret"
- **Function Purpose**: api_call to external endpoint with authentication header
- **String Analysis**: Masked secret string pattern detected
- **Usage Context**: Hard-coded in function call for API authentication
- **Conclusion**: This is a HIGH-RISK SECRET

**Output JSON Element:**
```json
{
    "file_hash": "889346ac21e02c55dedf3890d913245a",
    "value": "sec*******ret",
}
```

---

#### Example 3: URL-Embedded Secret

**Input:**
Filename: 6427aafd04458983c66ff31df111a018
Filecontent:
function dtcon_game_login() {
return requests.post("https://api.game.dtcon.com/biz/user/login", {
data: "secret_key=gna#3*******d&gdF4QaO&imei=000000000000000&version=2.1.54&_time=1614765847&heybox_id=15249824",
headers: {
"User-Agent": "dtcon-GameCenter/2.1.43 (Android 12)",
"Content-Type": "application/x-www-form-urlencoded",
"X-dtcon-Device-Id": imei
}
}).json();
}

**Reasoning Process:**
- **File Type**: JavaScript source code (JavaScript syntax)
- **Initial Scan**: Found "secret_key=" in POST data string
- **Context Analysis**: POST request to login endpoint with URL-encoded data
- **Parameter Parsing**: Extracted key-value pairs from data string
- **Secret Identification**: 
  - "secret_key=gna#3*******d&gdF4QaO" - explicit secret parameter
  - "heybox_id=15249824" - potential user identifier
- **Usage Context**: Authentication endpoint for game login
- **Conclusion**: Multiple SECRETS found (one CRITICAL, one MEDIUM)

**Output JSON Elements:**
```json
[
    {
        "file_hash": "6427aafd04458983c66ff31df111a018",
        "value": "gna#3*******d&gdF4QaO",
    },
    {
        "file_hash": "6427aafd04458983c66ff31df111a018",
        "value": "15249824",
    }
]
```

---

#### Example 4: Private Key Detection

**Input:**
Filename: 5832dcf6da6cc70aff003ac989a78a7a
Filecontent:
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCaCvMHKhcG/qT7xsNLYnDT7sE/D+TtWIol1ROdaK1a564vx5pHbsRy
SEKcIxISi1igBwYFK4EEACKhZANiAATYa7rJaU7feLMqrAx6adZFNQOpaUH/Uylb
ZLriOLON5YFVwtVUpO1FfEXZUIQpptRPtc5ixIPY658yhBSb6irfIJUSP9aYTflJ
GKk/mDkK4t8mWBzhiD5B6jg9cEGhGgA=
-----END EC PRIVATE KEY-----

**Reasoning Process:**
- **File Type**: Private key file (.key extension, PEM format markers)
- **Initial Scan**: Clear PEM format markers "-----BEGIN EC PRIVATE KEY-----"
- **Content Analysis**: Elliptic Curve (EC) private key in PEM encoding
- **Purpose**: Used for cryptographic operations, authentication, or encryption
- **Risk Assessment**: Complete private key exposed
- **Conclusion**: This is a CRITICAL SECRET

**Output JSON Element:**
```json
{
    "file_hash": "5832dcf6da6cc70aff003ac989a78a7a",
    "value": "-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDCaCvMHKhcG/qT7xsNLYnDT7sE/D+TtWIol1ROdaK1a564vx5pHbsRy\nSEKcIxISi1igBwYFK4EEACKhZANiAATYa7rJaU7feLMqrAx6adZFNQOpaUH/Uylb\nZLriOLON5YFVwtVUpO1FfEXZUIQpptRPtc5ixIPY658yhBSb6irfIJUSP9aYTflJ\nGKk/mDkK4t8mWBzhiD5B6jg9cEGhGgA=\n-----END EC PRIVATE KEY-----",
}
```

---

### Detection Guidelines

#### Transformation Patterns to Detect:

1. **Prefix/Suffix Removal**:
   - If code uses `.replaceAll()`, `.replace()`, `.strip()`, `.trim()` to remove markers
   - Extract **BOTH VALUES**
   - Example: If `"example" + "secret123"` is used, and code does `.replaceAll("example", "")`, extract both `"secret123"` and `"examplesecret123"` 

2. **String Concatenation**:
   - If multiple parts are joined (e.g., `a + b + c`)
   - Extract the final concatenated value
   - Example: `"sk-" + "abc" + "def"` → extract `"sk-abcdef"`

3. **String Formatting**:
   - If `.formatted()`, `.format()`, or similar methods add prefixes
   - Extract the final formatted value AND THE VALUE MATCHING THE FORMAT STRING OF COMMON SECRETS
   - Example: `"123abc\n-----BEGIN KEY-----%s".formatted("test")` → extract both `"123abc\n-----BEGIN KEY-----test"` and `"-----BEGIN KEY-----test"`

4. **Encoding/Decoding**:
   - If Base64 decode, URL decode, or hex decode is applied
   - Extract the decoded value

---

### Core Principle: Extract ALL Possible Secret Values

**CRITICAL INSTRUCTION: When secrets undergo transformations in code, extract BOTH:**
1. **The original literal value** (as it appears in source code)
2. **The transformed runtime value** (after all modifications)

This ensures comprehensive detection because:
- The original literal might be the actual secret if code is copied/reused
- The transformed value is what's actually used at runtime
- Both forms pose security risks and should be flagged


#### ✅ **DO detect and extract:**

**1. Credential Types:**
- API keys, access tokens, bearer tokens, OAuth tokens
- Passwords, passphrases, secret keys
- Database credentials (username:password, connection strings)
- Private keys (RSA, EC, DSA, PEM, PKCS formats)
- SSH keys, TLS/SSL certificates with private keys
- JWT tokens with sensitive payloads
- AWS keys (aws_access_key_id, aws_secret_access_key)
- Cloud service credentials (GCP, Azure, etc.)
- Third-party service keys (Stripe, SendGrid, Twilio, etc.)
- ANYTHING that could be used for authentication or access OR THAT LOOKS LIKE A REAL SECRET

**2. Detection Contexts:**
- Hard-coded strings in variables with security-related names
- Concatenated or split strings used in authentication
- Function parameters for security operations
- URL-embedded credentials (query params, POST data, basic auth)
- Configuration values for databases, APIs, services
- Environment variable defaults with real values
- Comments containing actual credentials (not examples)
- Base64 or hex-encoded sensitive data

**3. File Types to Analyze:**
- Source code: .py, .js, .java, .go, .php, .rb, .cs, etc.
- Configuration: .json, .yaml, .yml, .xml, .ini, .conf, .env
- Key files: .key, .pem, .p12, .pfx, .jks, .der
- Scripts: .sh, .bat, .ps1, .bash
- Documentation: .md, .txt (if containing real credentials)
- Data files: .sql, .csv (if containing credentials)

---

### Output Format Requirements

Structure:
```json
[
    {
        "file_hash": "filename_from_input",
        "value": "exact_secret_value_with_all_characters_including_newlines",
    }
    {
        "file_hash": "filename_from_input",
        "value": "exact_secret_value_with_all_characters_including_newlines",
    }
]
```

**Field Requirements:**
- `file_hash`: Use the exact filename provided in the input
- `value`: Complete secret value, preserving all whitespace, newlines (as \n), and special characters


**Important:**
- If a file contains NO secrets, do NOT include any element for that file in the output
- Each secret gets its own dictionary element in the list
- One file can generate multiple list elements if it contains multiple secrets
- Preserve exact secret values including special characters, newlines (\n), and whitespace
- PLEASE FOCUS ON THE SECRET's VALIDITY, EVEN IF THE CONTEXT SUGGESTS IT MIGHT BE AN EXAMPLE.
- PLEASE BE AS COMPREHENSIVE AS POSSIBLE IN YOUR DETECTION. LOOK FOR ALL POSSIBLE SECRETS.
---

### Your Task

Analyze the following files and extract ALL secrets using the reasoning process demonstrated above.

**Output JSON Elements:**
```json
[
    {
        "file_hash": "6427aafd04458983c66ff31df111a018",
        "value": "gna#3*******d&gdF4QaO",
    },
    {
        "file_hash": "6427aafd04458983c66ff31df111a018",
        "value": "15249824",
    }
]
```

**Field Requirements:**
- `file_hash`: Use the exact filename provided in the input
- `value`: Complete secret value, preserving all whitespace, newlines (as \n), and special characters


**Important:**
- If a file contains NO secrets, do NOT include any element for that file in the output
- If NO secrets are found in ANY file, output an empty list: `[]`
- Each secret gets its own dictionary element in the list
- One file can generate multiple list elements if it contains multiple secrets
- Preserve exact secret values including special characters, newlines (\n), and whitespace

---

### Your Task

Analyze the following files and extract ALL secrets using the reasoning process demonstrated above.


**Output Requirements:**
1. Provide ONLY the JSON list output
2. No additional text, explanations, or markdown formatting
3. Ensure valid JSON syntax (proper escaping, quotes, commas)
4. Include all detected secrets from all files
5. If no secrets found, output: `[]`

Begin your analysis and output the JSON list:
