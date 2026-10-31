# 落日二号乙漏洞挖掘报告 — 20261031-174457-8c3c8a

- 生成时间：2026-10-31T09:44:57.958932+00:00
- 输入 URL：`http://127.0.0.1:18081/054.php`
- 输入模式：`url`
- SHA256：`839d939c3c43f9f891dceddd5d1ccf2148d2f9c259676cb310b837635b03d8a2`
- 文件：0（文本 0）
- 语言：
- 框架：http, awvs
- 端点：1
- 版本：1.0.0
- 严重度档位：`low`（min_confidence=0.6）
- 确定性规则候选生成：已禁用（zip 模式候选来自 LLM 深挖）
- 策略抑制候选：0 条
- 结构化报告：`report.json`（契约）、`report.schema.json`、`report.sarif`、`report.html`

## 1. 执行摘要

URL 模式：AWVS 来源 awvs-local-probe，产出 1 条动态候选，覆盖 1 种漏洞类型；1 条已生成可重放的 POC。结论仍为 candidate，需落日验证动态确认。

共 **1** 条 finding；**1** 条已生成 POC；**0** 条二次注入链；**0** 条 Prompt 注入迹象，隔离 **0** 个文件。

> 本管线不执行 POC、不搭建沙箱、不做动态验证。所有 verdict 为 `candidate` 或 `external`，需要在授权环境人工复核；URL 模式的 POC 由落日验证动态执行。

## 2. LLM 安全防护（SafetyGuard）

未检测到 Prompt 注入迹象。

## 2.1 LLM 深挖（LLM-finding / DeepFinder）

- 未执行：LLM 未启用

## 3. Findings

### F-1: AWVS: Cross-site Scripting (XSS)

- **类型**：`xss` / CWE-79
- **严重度**：`high`
- **置信度**：`0.78`
- **结论**：`candidate` / 证据等级 `external_only`
- **位置**：外部扫描端点 `/054.php`
- **来源**：`awvs`

**描述**

AWVS reported `Cross-site Scripting (XSS)` at `http://127.0.0.1:18081/054.php`. Evidence: Local AWVS-compatible probe observed unencoded script reflection. baseline HTTP 200 (4725 bytes); attack HTTP 200 (4742 bytes); marker='<script>alert(1)</script>'.. This URL-mode finding has no source file/line; it must be validated dynamically.

**source / sink**

- source：form `name` @ http://127.0.0.1:18081/054.php
- sink：GET /054.php

**利用链**

| # | 位置 | 描述 | 数据状态 | 绕过原因 |
|---|---|---|---|---|
| 1 | `http://127.0.0.1:18081/054.php` | AWVS identified Cross-site Scripting (XSS) |  |  |
| 2 | `GET /054.php` | Replay request via form `name` |  |  |

**POC**

AWVS candidate on http://127.0.0.1:18081/054.php (Cross-site Scripting (XSS)). Injection channel: form `name`. Raw request is preserved; the verifier resolves TARGET and replays it.

1. **Baseline request**

```http
curl -sS -i -X GET 'http://TARGET:8080/054.php?name=SafeText' \
  -H 'User-Agent: Sunset-AWVS-Probe/1.0' \
  -H 'Accept: */*'
```
预期：HTTP 200 and the normal application response.

2. **Replay the AWVS attack request (跨站脚本)**

```http
curl -sS -i -X GET 'http://TARGET:8080/054.php?name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E' \
  -H 'User-Agent: Sunset-AWVS-Probe/1.0' \
  -H 'Accept: */*'
```
预期：The response contains the raw script payload without HTML encoding.

3. **Compare baseline and attack responses**
预期：A security-relevant differential appears.

- payload：`<script>alert(1)</script>`
- POC 目录：`poc/URL-407d318b0293`
- 风险提示：POC 叙述未明确标注 source→sink 注入点, 原始 payload 未直接出现在请求文本中，可能经过 URL 编码
- 执行状态：未执行（`executed=False`）

**影响**

AWVS dynamic candidate; impact depends on the endpoint and payload. CWE=CWE-79.

**CVE / CWE 论证**

AWVS dynamic candidate `Cross-site Scripting (XSS)` (CWE=CWE-79) at `http://127.0.0.1:18081/054.php`. No source mapping is claimed in URL mode; dynamic replay is the evidence path.

**修复建议**

Encode output for the correct context and add a restrictive CSP.

**验证说明**

AWVS candidate from URL mode. Not verified by this pipeline; 落日验证 should replay the preserved request against the allowlisted target.

**外部佐证**

- awvs: Cross-site Scripting (XSS) @ http://127.0.0.1:18081/054.php

## 4. 二次注入（SecondOrderAnalyzer）

本次未发现 store→read→sink 闭环的二次注入链。

## 5. AWVS 联动

- 输入模式：`url`
- 导入结果：1 条
- 关联明细：0 条
- 目标种子：`awvs/targets.json`
- 说明：URL 模式下 AWVS 是候选提出组件；本管线消费其 URL/请求/证据并生成 POC，不执行扫描；动态确认由落日验证完成。

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
| `xss` | CWE-79 | 是 | 1 |
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
| safety_guard | 安全防护 | 0.0 | 否 |
| surface_mapper | 攻击面测绘 | 0.0 | 否 |
| candidate_screener | 候选筛选 | 0.0 | 否 |
| vulnerability_analyzer | 漏洞分析 | 0.0 | 否 |
| poc_writer | POC 生成 | 0.0 | 否 |
| coordinator | 管线协调 | 0.0 | 否 |

## 8. 限制

- 只做源码静态分析，不构建、不部署、不执行 POC、不搭建沙箱；
- finding 的 `verdict` 为 `candidate`，不是动态确认；
- 需要授权环境、人工复核与 AWVS 结果才能升级为 confirmed；
- 被 SafetyGuard 隔离的文件正文不会进入 LLM；隔离文件不会产生静态候选。
