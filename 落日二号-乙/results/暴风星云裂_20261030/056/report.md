# 落日二号乙漏洞挖掘报告 — 20261030-225215-dcb677

- 生成时间：2026-10-30T14:52:38.986970+00:00
- 输入：`C:\Users\liyuf\Desktop\794\暴风星云裂\056.zip`
- 输入模式：`zip`
- SHA256：`ddeedf015a89af3c4e7d2a26f3eadc8b063046e52cecc3d299334e66c93a1d75`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.0.0
- 严重度档位：`high`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总的 findings 为空：去重后没有任何已确认漏洞，with_poc=0，因此没有 HTTP POC，也没有静态证据 POC。覆盖统计显示仓库仅 1 个文件（056.php，PHP，22 行，约 1.2KB），无框架、无路由、无端点清单，endpoints=0。攻击面测绘仅给出统计元数据（source 热点 3 处、sink 热点 1 处，均在 056.php），未提供任何代码行，因此无法确认 source/sink 的具体函数与行号，也无法判定 command_injection / sql_injection / path_traversal / LFI / ssrf / xss 等类型。最高危的候选方向是 056.php 中「3 个 source 汇聚到 1 个 sink」的污点传播路径，以及文件包含/路径拼接与命令执行类汇点，但这些均为待确认假设，不构成漏洞结论。POC 不齐全（0 条），且因缺少源码内容，本次无法产出任何可复现 POC 文本。

共 **0** 条 finding；**0** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 1342 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 056.php（22 行，完整展示）。该脚本为 DVWA 风格的留言板写入片段：入口为 POST 参数 btnSign/mtxMessage/txtName（056.php:3-6），随后对 $message 与 $name 分别执行 stripslashes（056.php:9）与 mysqli_real_escape_string（056.php:10、13），最终在 056.php:16 拼接为 INSERT 语句并在 056.php:17 通过 mysqli_query 执行。关键判断：两个进入 SQL 字符串的变量都经过 mysqli_real_escape_string 处理，且该调用以 $GLOBALS["___mysqli_ston"] 这一真实连接对象为参数（is_object 分支成立），因此单引号、反斜杠等元字符会被正确转义，常规一次注入链不闭合；stripslashes 在转义之前执行，不会削弱 mysqli_real_escape_string 的转义效果（顺序为 stripslashes → real_escape_string，不存在先转义后去反斜杠的绕过）。未发现 include/require、eval、system/exec、file_get_contents、unserialize 等其它 sink，也无 md5/sha1、rand/mt_rand、setcookie、X-Forwarded-For 信任等配置类证据。因此按 min_severity=high、min_confidence=0.6 的策略，本次无可交付的 CVE 级发现，返回空数组。未闭合线索：(1) 若 ___mysqli_ston 未初始化或非对象，代码走 trigger_error 分支并返回空串，此时注入不可达，反而说明不存在可利用注入；(2) 该片段依赖外部包含方建立数据库连接与字符集设置，若连接字符集为 GBK 等宽字节且未调用 set_charset，理论上存在宽字节注入可能，但连接建立代码不在 code_pack 内，无法确认，故不报告；(3) 输出侧无回显（仅 die 输出 mysqli_error），存在基于报错的注入信息泄露可能，但同样受转义阻断，不构成闭合链。

未覆盖 / 证据缺口：
- 数据库连接建立与字符集设置代码不在 code_pack 内，无法评估宽字节注入（GBK）可能性
- 无 php.ini / Web 服务器配置，无法判断 magic_quotes、allow_url_include 等环境因素
- 无端点与路由信息，无法确认该脚本是否被其它页面包含或存在前置认证
- 仓库仅 1 个文件，无法进行跨文件污点追踪与二次注入评估

## 3. Findings

未发现满足阈值的候选。

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`zip`
- 导入结果：0 条
- 关联明细：0 条
- 目标种子：`awvs/targets.json`
- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 0 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 0 |
| `deserialization` | CWE-502 | 是 | 0 |
| `ssti` | CWE-1336 | 是 | 0 |
| `auth_bypass` | CWE-287 | 是 | 0 |
| `idor` | CWE-639 | 是 | 0 |
| `xxe` | CWE-611 | 是 | 0 |
| `xss` | CWE-79 | 是 | 0 |
| `business_logic` | CWE-840 | 是 | 0 |
| `other` | CWE-693 | 是 | 0 |
| `rce` | CWE-94 |  | 0 |
| `code_injection` | CWE-94 |  | 0 |
| `expression_injection` | CWE-917 |  | 0 |
| `ldap_injection` | CWE-90 |  | 0 |
| `xpath_injection` | CWE-643 |  | 0 |
| `open_redirect` | CWE-601 |  | 0 |
| `csrf` | CWE-352 |  | 0 |
| `file_upload` | CWE-434 |  | 0 |
| `race_condition` | CWE-367 |  | 0 |
| `weak_crypto` | CWE-327 |  | 0 |
| `weak_hash` | CWE-328 |  | 0 |
| `weak_random` | CWE-330 |  | 0 |
| `hardcoded_secret` | CWE-798 |  | 0 |
| `trust_boundary` | CWE-501 |  | 0 |
| `log_injection` | CWE-117 |  | 0 |
| `insecure_cookie` | CWE-614 |  | 0 |
| `information_disclosure` | CWE-200 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 4.25 | 是 |
| surface_mapper | 攻击面测绘 | 8.76 | 是 |
| deep_finder | LLM 深挖 | 4.88 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 5.75 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
