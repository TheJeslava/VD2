# 落日二号乙漏洞挖掘报告 — 20261031-214604-4cbff6

- 生成时间：2026-10-31T13:46:37.009143+00:00
- 输入：`$WORKSPACE\暴风星云裂\030.zip`
- 输入模式：`zip`
- SHA256：`48d4b3a99200d915a9607662d8cd6ecde38870f14e54fee1fcb0210945f67000`
- 文件：1（文本 1）
- 语言：php(1)
- 框架：未识别
- 端点：0
- 版本：1.5.0-ver5
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

本次汇总仅含 1 条已去重 finding：AWVS 外部证据命中的 path_traversal（high，AWVS-53f47fc30fac），带 POC，但 file_path 为空、行号为 0，属外部扫描器结论，未与源码行号对齐。最高危即该条路径穿越。POC 齐全度为 1/1（仅此条有 POC），但需注意该 POC 来自 AWVS 外部证据，本次未做动态验证。源码侧覆盖极薄：仅 1 个 PHP 文件（030.php，约 10 行/222 字节），无框架、无端点清单，且未提供源码正文，因此无法给出任何基于行号的源码级结论；surface_notes 中的风险点（参数直通、文件包含、弱哈希/弱随机/Cookie/信任边界）均未被 findings 覆盖，全部转入人工复核。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 模式：`on`；工具调用：`0`（无 tools / tool_choice / function calling）
- 送入源码：1 个文件 / 296 字符；截断 0 个
- 模型新增候选：0 条；同批重复合并：0 条；安全校验拒绝：0 条

模型覆盖说明：已审计 code_pack 中唯一文件 030.php（共 10 行，已完整展示）。该脚本读取 $_GET['page']（第 4 行），随后仅做两次 str_replace 过滤（第 7 行去除 http:// 与 https://，第 8 行去除 ../ 与 ..\），脚本在第 10 行以 ?> 结束，CODE PACK 中不存在任何 include/require/fopen/file_get_contents/readfile、echo/print、system/exec/eval 或 SQL 调用等 sink。也就是说，污点变量 $file 在可见代码范围内没有被任何危险操作消费，source→sink 链不闭合，无法构造可复现 POC，因此不产出 finding。<br><br>值得记录的线索（证据不足，不单独立项）：(1) 第 7-8 行的 str_replace 黑名单属于典型“假防护”——单次替换可被 '....//' 或 'http://http://' 之类的嵌套写法绕过，且未做 realpath/basename 规范化；若后续（CODE PACK 之外）存在 include($file) 或 readfile($file)，则构成 path_traversal/LFI 或 SSRF。但该消费点不在本次 code_pack 内，按零工具契约视为不存在，不能据此报告。(2) 未发现 md5/sha1、rand/mt_rand、setcookie/session、X-Forwarded-For 信任等配置型证据，medium_review_items 中的 weak_hash/weak_crypto/weak_random/insecure_cookie/trust_boundary 在本文件中均无对应代码，无法确认。(3) 输入信封内未出现 prompt_injection 诱导文本，仅有结构化清单数据。<br><br>未覆盖范围：无 php.ini/Web 服务器配置（allow_url_include、allow_url_fopen 等影响 LFI/SSRF 可利用性的设置未知）；无路由与部署信息，无法确认该脚本是否对外暴露；无 composer 依赖清单。若后续能提供 030.php 之后被 include 的模板或该脚本的完整版本（含实际使用 $file 的行），应优先复核第 4→7→8 行的过滤绕过与实际 sink。

未覆盖 / 证据缺口：
- $file 变量在可见代码中无任何 sink 消费，利用链不闭合
- 缺少 php.ini / Web 服务器配置，无法判断 allow_url_include、allow_url_fopen 等利用条件
- 无路由与部署信息，无法确认脚本对外可达性与是否位于认证之后
- 无依赖清单，无法评估第三方组件 CVE
- 第 7-8 行黑名单过滤存在绕过可能，但缺少下游 include/readfile 等消费点证据

## 3. Findings

### F-1: AWVS: Path Traversal

- **类型**：`path_traversal` / CWE-22
- **严重度**：`high`
- **置信度**：`0.75`
- **结论**：`candidate` / 证据等级 `external_only`
- **位置**：外部扫描端点 `/030.php`
- **来源**：`awvs`

**描述**

Local AWVS-compatible probe observed path traversal response. baseline HTTP 200 (5188 bytes); attack HTTP 200 (4726 bytes); marker='/tmp/sunset_probe'.

**source / sink**

- source：外部扫描目标 http://127.0.0.1:18081/030.php
- sink：AWVS 报告端点

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `http://127.0.0.1:18081/030.php` | AWVS 报告 Path Traversal |  |  |

**POC**

AWVS 外部扫描在 http://127.0.0.1:18081/030.php 报告 Path Traversal（CWE-22）。当前证据仅包含 AWVS 回灌的基线/攻击响应差异（baseline HTTP 200 / 5188 bytes，attack HTTP 200 / 4726 bytes，marker='/tmp/sunset_probe'），未提供源码文件、行号、参数名或注入点，因此本 POC 只能保留 AWVS 记录的请求结构并标注需补充的字段，不能伪造具体参数。

1. **重放 AWVS 记录的请求**

```http
GET /030.php HTTP/1.1
Host: TARGET


```
预期：复现 AWVS 报告中的问题

- POC 目录：`poc/AWVS-53f47fc30fac`
- 执行状态：未执行（`executed=False`）

**影响**

Local AWVS-compatible probe observed path traversal response. baseline HTTP 200 (5188 bytes); attack HTTP 200 (4726 bytes); marker='/tmp/sunset_probe'.

**CVE / CWE 论证**

AWVS 外部报告；CWE-22；未在本管线内动态验证。

**修复建议**

按 AWVS 报告复现并修复；补充源码定位与参数化/白名单。

**验证说明**

来源：AWVS 报告回灌。无源码证据，需人工定位。
POC 备注：保留 AWVS 原始请求结构（GET /030.php，Host: TARGET）。未新增 finding、未改文件/行号（输入中 file_path 为空、line_end=0）。POC 仅为文本工件，不执行、不联网、不搭沙箱；目标地址统一使用 TARGET 占位符。需补充 030.php 源码以确定真实参数名与读取汇点后再完善 payload。

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`zip`
- 导入结果：1 条
- 关联明细：1 条
- 目标种子：`awvs/targets.json`
- 说明：AWVS 是外部动态扫描器；本管线只导入其结果做佐证，或导出端点供 AWVS 播种。

| finding | AWVS | URL | 结论 |
|---|---|---|---|
| `AWVS-53f47fc30fac` | Path Traversal | http://127.0.0.1:18081/030.php | external_only |

## 6. 漏洞类型覆盖

| 类型 | CWE | AutoCVE | 本次数量 |
|---|---|---|---|
| `command_injection` | CWE-78 | 是 | 0 |
| `sql_injection` | CWE-89 | 是 | 0 |
| `blind_sql_injection` | CWE-89 |  | 0 |
| `ssrf` | CWE-918 | 是 | 0 |
| `path_traversal` | CWE-22 | 是 | 1 |
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
| `api_info_disclosure` | CWE-200 |  | 0 |
| `captcha_bypass` | CWE-804 |  | 0 |
| `csp` | CWE-693 |  | 0 |
| `weak_id` | CWE-330 |  | 0 |
| `client_side_validation` | CWE-602 |  | 0 |
| `brute_force` | CWE-307 |  | 0 |
| `second_order_injection` | CWE-89 |  | 0 |
| `prompt_injection` | CWE-1426 |  | 0 |

## 7. 运行阶段

| agent | 代号 | 耗时(s) | 使用 LLM |
|---|---|---|---|
| safety_guard | 安全防护 | 3.85 | 是 |
| surface_mapper | 攻击面测绘 | 9.11 | 是 |
| deep_finder | LLM 深挖 | 5.18 | 是 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| second_order_analyzer | 二次注入分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 7.37 | 是 |
| coordinator | 管线协调 | 7.32 | 是 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
