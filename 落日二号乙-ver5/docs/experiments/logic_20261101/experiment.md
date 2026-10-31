# 勇旭：隐性逻辑漏洞本地对照实验

- UTC 时间：2026-10-31T18:56:02.209551+00:00
- HTTP 实验来源：自行编写的最小教学复现，不是原始 DVWA / PHP 样本的动态运行记录。
- 绑定：127.0.0.1 随机端口；Python 标准库；未调用 LLM、AWVS 或任何外部目标。
- 静态分析与 HTTP 实验使用同一组 vulnerable.py / fixed.py 函数。
- 可信策略由实验方在源码包之外提供；缺上下文样本只分析、不执行。
- 动态结论根据服务端状态变化和响应共同判断，不是仅检查 HTTP 200。
- 每个准备步骤也核对预期 HTTP、完整业务状态及各会话状态；前置条件不成立时该场景判为失败。
- 验证码用确定性的服务端测试桩代替，只验证流程状态与会话绑定，不测试验证码算法。
- 实验未覆盖生产持久化、并发、完整认证和所有业务规则。

静态对照：11/11 满足预期。
HTTP 对照：32/32 满足预期。

## 静态判定

| 规则 | 类别 | 预期 | 实际 | 通过 |
|---|---|---|---|---|
| vulnerable-reset_password | workflow_bypass | candidate | candidate | True |
| vulnerable-reset_password_client_flag | workflow_bypass | candidate | candidate | True |
| vulnerable-update_order | object_authorization | candidate | candidate | True |
| vulnerable-purchase | business_constraint | candidate | candidate | True |
| fixed-reset_password | workflow_bypass | guarded | guarded | True |
| fixed-reset_password_client_flag | workflow_bypass | guarded | guarded | True |
| fixed-update_order | object_authorization | guarded | guarded | True |
| fixed-purchase | business_constraint | guarded | guarded | True |
| missing_context-reset_password | workflow_bypass | needs_context | needs_context | True |
| missing_context-update_order | object_authorization | needs_context | needs_context | True |
| missing_context-purchase | business_constraint | needs_context | needs_context | True |

## 仓库原始 PHP 样本（仅静态）

- 014.php：candidate；动态验证：未执行。
- 015.php：candidate；动态验证：未执行。

## HTTP 与状态对照

| 场景 | 版本 | HTTP | 状态改变 | 预期改变 | 通过 |
|---|---|---|---|---|---|
| workflow_direct | vulnerable | 200 | True | True | True |
| workflow_forged_client_flag | vulnerable | 200 | True | True | True |
| workflow_missing_client_flag | vulnerable | 403 | False | False | True |
| workflow_verified | vulnerable | 200 | True | True | True |
| workflow_client_verified | vulnerable | 200 | True | True | True |
| workflow_wrong_verification | vulnerable | 200 | True | True | True |
| workflow_other_session | vulnerable | 200 | True | True | True |
| workflow_replay | vulnerable | 200 | True | True | True |
| object_other_order | vulnerable | 200 | True | True | True |
| object_own_order | vulnerable | 200 | True | True | True |
| object_forged_user | vulnerable | 200 | True | True | True |
| quantity_negative | vulnerable | 200 | True | True | True |
| quantity_zero | vulnerable | 200 | True | True | True |
| quantity_valid | vulnerable | 200 | True | True | True |
| quantity_wrong_type | vulnerable | 400 | False | False | True |
| unauthenticated | vulnerable | 401 | False | False | True |
| workflow_direct | fixed | 403 | False | False | True |
| workflow_forged_client_flag | fixed | 403 | False | False | True |
| workflow_missing_client_flag | fixed | 403 | False | False | True |
| workflow_verified | fixed | 200 | True | True | True |
| workflow_client_verified | fixed | 200 | True | True | True |
| workflow_wrong_verification | fixed | 403 | False | False | True |
| workflow_other_session | fixed | 403 | False | False | True |
| workflow_replay | fixed | 403 | False | False | True |
| object_other_order | fixed | 403 | False | False | True |
| object_own_order | fixed | 200 | True | True | True |
| object_forged_user | fixed | 403 | False | False | True |
| quantity_negative | fixed | 403 | False | False | True |
| quantity_zero | fixed | 403 | False | False | True |
| quantity_valid | fixed | 200 | True | True | True |
| quantity_wrong_type | fixed | 400 | False | False | True |
| unauthenticated | fixed | 401 | False | False | True |

完整请求、服务端状态前后值、分析证据和 SHA-256 见 experiment.json。

## 复现

在 ver5 目录执行：

    python -m examples.logic_lab.run_experiment --out docs/experiments/logic_20261101
    python -m unittest discover -s tests -p test_logic_lab.py -v
