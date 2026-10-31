# 本次交付验证记录

基础提交：VD2 `129b8e0`，首次实现 `cc29898`；本记录已更新为用户要求复查后的结果。实现分支 `xu`，功能集中在 `落日二号乙-ver5`。

## 实际执行的检查

| 检查 | 命令/方式 | 结果 |
|---|---|---|
| 核心规则与反例 | `tests/test_logic_analysis.py` | 29 项通过 |
| 管线、规则来源、输出契约与模型边界 | `tests/test_logic_integration.py` | 8 项通过 |
| 本地 HTTP 实验与静态对照 | `tests/test_logic_lab.py` | 9 项通过 |
| Python 审查反例 | `tests/test_logic_review_python.py` | 13 项通过 |
| PHP 审查反例 | `tests/test_logic_review_php.py` | 13 项通过 |
| 接入审查反例 | `tests/test_logic_review_integration.py` | 4 项通过 |
| 实验准备步骤审查反例 | `tests/test_logic_review_lab.py` | 6 项通过 |
| 全套回归 | `unittest.defaultTestLoader.discover('tests')`，等价于标准 discover 命令 | `Ran 108 tests`，`OK (skipped=4)`，无失败/错误 |
| 命令行自检 | `python -m sunset selftest` | 5 个自检项全部通过 |
| 独立实验存档 | `python -m examples.logic_lab.run_experiment --out docs/experiments/logic_20261101` | 静态 11/11、HTTP/状态 32/32 满足预期 |
| 主流程接入 | `run_pipeline` + 显式 `Settings(llm_mode="off")` | 4 candidate、4 guarded、3 needs_context；4 个专属 Finding；零阶段错误、零报告契约错误 |
| 代码格式 | `git diff --check` | 通过 |

测试在 Python 3.14 环境执行，业务模块仅用标准库。目标源码只解析、不导入；本地实验导入并执行的是我们自己编写的固定教学样本。未调用真实模型 API 或外部扫描服务。

4 处跳过来自原仓库缺少 `lite/BenchmarkTest00002.zip`，涉及该样本的测试/测试类；没有创建假样本来替代它。模块相关 82 项测试均通过，其中本轮审查新增 36 项。实际运行日志见 [tests.log](tests.log)，机器可读摘要与本轮分析器哈希见 [tests_summary.json](tests_summary.json)。

## 原有测试修正

在原始 `129b8e0` 的独立副本上运行基线：`Ran 26 tests`，2 个失败、4 处跳过。两个失败断言仍假定 ZIP 管线不生成静态候选，与该提交中已恢复的确定性规则引擎矛盾：

- `TestLogicCoverage.test_idor_and_business_logic`：更新为要求已有 Java 夹具检测出 IDOR 和业务逻辑候选，并确认仍需验证。
- `TestSecurityGuard.test_quarantine_does_not_block_detection`：更新为要求安全隔离仍保留离线规则检测，检查来源、文件、未执行标记及零模型调用。

没有关闭测试或放宽到“任意结果都算通过”。缺失样本对应的跳过仍保留。

## 复核后补充的反例

- `if` 中只有一条分支完成检查，或条件通过 OR 被客户端标记绕过。
- 检查发生在操作之后；失败分支仅显示错误但没有终止。
- 检查后重新赋值、通过别名修改对象、表达式内副作用。
- 检查 A 对象却把 B 对象传给敏感操作；对象只出现在备注参数中。
- 客户端请求变量重命名为 `payload`、再经 `packet` 别名传入，仍不能被当作可信订单。
- 辅助鉴权、装饰器、异常/循环、缺业务规则等情况保留 needs_context。
- 模型返回未知 ID、修改状态或编造文件，不能改变确定性结论；隔离文件不送给该模块的模型复核。

## 如何读实验结论

`experiment.json` 保存完整请求、响应状态、操作前后业务状态、精确预期状态、规则/样本/分析器哈希。复查后每个准备步骤也必须通过 HTTP、业务状态和会话状态核对。动态结果只证明这组教学样本的行为；不证明未知项目的检测率，也不表示原始 PHP/DVWA 已完成动态验证。

审查复现的问题及修复措施见 [复查记录](../../LOGIC_REVIEW.md)。首次实现中未被覆盖的边界已补入测试；不能用首次测试通过来替代这些反例验证。

`pipeline_summary.json` 和 `pipeline/` 是同一源码包通过主扫描流程的记录。其 POC 为人工验证计划，目标 POC 未执行；独立本地实验的成功不会改写主扫描报告中的 candidate。

可配置三类规则的第一版语法支持是 Python AST；PHP 仅适配分步验证码改密模式。对象授权和业务约束在其他 PHP 项目上的通用分析，仍需后续语言适配。真实 LLM 调用效果本次未测，仅验证了接口及输出限制。
