# 勇旭：隐性逻辑漏洞专属判定与验证

本模块对应附加任务“针对二次注入、隐性逻辑漏洞设计专属挖掘与验证流程”中的隐性逻辑部分。它接在 ver5 的源码管线中，与二次注入模块并列。新增的判定不会自动执行待审代码或 POC。

## 1. 解决什么问题

普通输入到危险函数的追踪，难以说明“操作之前本应满足什么业务条件”。本模块把规则明确表示成：

> 在某个函数执行指定操作之前，指定条件必须在服务端成立。

支持三类规则：

| 类别 | 需要检查的问题 | 本次最小实验 |
|---|---|---|
| `workflow_bypass` 流程绕过 | 必须完成的步骤是否保护最终操作 | 服务端未确认验证码通过就改密码 |
| `object_authorization` 对象级越权 | 操作的对象是否属于当前登录用户 | Alice 修改 Bob 的订单 |
| `business_constraint` 业务约束缺失 | 业务输入是否满足服务端约束 | 负数或零数量进入购买操作 |

这些实验是用于验证模块的最小教学程序，不是发现了分析工具本身的漏洞，也不是部署并完整运行了 DVWA。

## 2. 通用性与边界

三类规则共用分析器、证据格式、报告与验证步骤。更换文件、函数、操作和前置条件，可以检查新的业务代码，不依赖样本编号或固定文件名。

第一版具体支持：

- **Python 显式业务规则**：使用标准库 AST 分析指定函数中的分支和提前返回。规则由操作者从外部 JSON 提供；支持的局部语法可判断条件是否覆盖到操作的路径。
- **PHP 自动流程线索**：识别“一个客户端 step 分支调用验证码，另一个分支执行改密 SQL”的有限模式。仓库的 `014.php`、`015.php` 用于该适配器检查。
- **LLM 辅助复核**：沿用管线已配置的模型，仅补充解释与反证方向；不能修改确定性状态、置信度、源码位置，也不能把候选升级成动态确认。没有模型配置也能完成规则分析与本地实验。

这不是任意语言的完整程序验证器。跨服务鉴权、中间件、复杂别名、循环、异常、动态分派等未完整建模的情况需要补充上下文。PHP 适配器暂未实现通用对象授权和金额数据流分析；这些类型的可复现实验使用 Python。不能把该实现描述成“所有 PHP 业务漏洞通用扫描器”。

## 3. 规则由谁提供

程序不能自行认定所有网站都必须先付款后发货。业务规则应由需求文档和开发者确认，再由操作者通过 `--logic-policy` 指定文件。待审 ZIP 中碰巧有 `policies.json`、README 或注释，不会被自动当成可信规则。

规则文件格式：

```json
{
  "version": 1,
  "rules": [
    {
      "id": "reset-requires-captcha",
      "category": "workflow_bypass",
      "file": "handlers.py",
      "function": "change_password",
      "operation": "store.change_password",
      "required_condition": "session.get('captcha_passed') is True",
      "description": "改密前必须完成服务端验证码验证",
      "trusted_inputs": ["session"],
      "context_complete": true
    }
  ]
}
```

- `file` 是 ZIP 内相对路径；`function` 是函数名或明确的类方法名。
- `operation` 指定敏感调用；`required_condition` 指定执行前的必要条件。表达式仅解析语法，绝不 `eval` 或 `exec`。
- 对象授权与数值约束还需要 `operation_bindings`，把被检查的对象/数值绑定到真正操作的参数。例如订单更新的第一个参数应为 `order['id']`，则写 `"operation_bindings": {"0": "order['id']"}`；购买函数的第二个参数应为 `quantity`，则写 `{"1": "quantity"}`。数字是从 0 开始的位置，也支持关键字参数名。缺少绑定或实际调用不一致时保留证据不足，避免“检查 A 却操作 B”。
- `trusted_inputs` 声明需要保持可信来源的变量。操作者应确认 `session` 来自服务端会话，不是由客户端请求体替代。
- `context_complete=true` 是操作者对本规则检查范围的明确声明：已考虑调用者、认证入口、服务层与外部业务约束。不能为了获得更多候选就把未知上下文改成 true；缺省 false 时结论保留为证据不足。
- 检查的是提供的具体必要条件。语义相近但超出当前分析能力的写法，需要调整规则或人工复核，不能据此声称缺少所有保护。

## 4. 分析过程

1. 定位规则所指的函数和敏感操作，记录原始源码行号。
2. 跟踪分支：例如 `if not condition: return` 可在后续路径上建立条件；`if condition: operation()` 可保护其分支内操作。
3. 分开处理不同路径，不把 `condition or client_flag` 当成 condition 必然成立。
4. 检查条件依赖的值是否被重新赋值或可能被修改；出现不能证明的调用、控制流或上下文时，保留证据缺口。
5. 输出判定、业务规则、源码证据、缺失信息，以及正常流程/异常流程/修复版的对照验证步骤。

输出状态：

| 状态 | 含义 | 是否作为专属模块 Finding |
|---|---|---|
| `candidate` | 在声明的范围内发现未被指定条件保护的操作路径，仍需动态验证 | 是，且遵守严重度与置信度阈值 |
| `guarded` | 指定条件在受支持的局部分析中保护该操作 | 否；不等于整个系统安全 |
| `needs_context` | 缺规则、源码、调用关系或可信来源等证据 | 否，保留待复核记录 |

## 5. 与现有管线的连接

```text
源码导入 → 安全隔离 → 通用规则/LLM候选 → 通用分析
        → 二次注入分析 → 隐性逻辑判定 → POC计划 → 汇总报告
```

`LogicAnalyzerAgent` 调用 `analyze_logic`。只有 candidate 转为 `origin=logic_specialist` 的 Finding，保留 `verdict=candidate`、`evidence_level=static_candidate`、`needs_verification=true`。相同类型、文件和操作位置的已有候选合并时保留其来源。

没有确认真实路由、账号和状态读取方法时，输出的是 `poc_readme.md` 人工验证计划，契约状态为 `not_executable`。不为任意源码编造一个可以直接发送的 HTTP 请求。现有汇总的“含 POC”计数也包含这种文本工件，不等于可执行验证脚本数。

新增报告：

- `logic_analysis.json`：所有判定，包含 guarded、needs_context、模型补充意见和规则文件哈希。
- `report.json`、`result.json` 的 `logic_assessments`：相同结构化数据。
- `report.md`：可阅读的隐性逻辑判定表。

既有通用扫描器仍可能报告其自身的启发式候选。某条规则的 guarded 不会删除别的类型或别的操作上的问题，也不代表整个项目扫描结果应该为空。

## 6. 不使用凭据的调用方式

可以直接构造配置，避免读取工作目录中的 `.env`：

```python
from pathlib import Path
from sunset.config import Settings
from sunset.pipeline import run_pipeline

result = run_pipeline(Path("app.zip"), Settings(
    llm_mode="off",
    logic_policy="trusted-policy.json",
    output_dir=Path("results/logic-review"),
    work_dir=Path(".work/logic-review"),
))
```

已有正常配置的源码扫描也可以通过 CLI 增加 `--logic-policy trusted-policy.json`。该选项不适用于只有 URL、没有源码的模式。配置文件错误会直接报错，避免静默忽略用户指定的业务规则。

## 7. 实验应如何判定成功

实验需要同时有漏洞版、修复版和正常流程控制，保存请求、响应及真实状态变化：

- 流程绕过：未验证时改密是否真的发生；修复版能否阻止绕过并允许正常改密。
- 对象越权：Alice 的请求是否真的改变 Bob 的订单；修复版拒绝跨用户操作但允许修改自己的订单。
- 业务约束：负数和零数量是否进入业务状态；修复版拒绝异常数量并保留正常购买。

静态检查和动态实验分开记录。固定样本上的成功率不代表未知项目的准确率；演示程序的实验不能替代原始 PHP 样本的运行证明。

本次已执行：静态对照 11/11、HTTP 与状态对照 32/32 满足预期。原始 `014.php`、`015.php` 静态识别为候选。详细数据见 [实验记录](experiments/logic_20261101/experiment.md)、[完整请求与状态 JSON](experiments/logic_20261101/experiment.json)。主流程接入输出见 [管线报告](experiments/logic_20261101/pipeline/report.md)，回归测试与限制见 [验证记录](experiments/logic_20261101/validation.md)。

## 8. 代码入口

| 文件 | 职责 |
|---|---|
| `sunset/logic_analysis.py` | 有界静态判定、PHP 流程适配、证据与缺口 |
| `sunset/agents/logic_analyzer.py` | 规则加载、LLM 复核边界、Finding 转换、管线连接 |
| `prompts/logic_analyzer.md` | 隐性逻辑复核提示词 |
| `examples/logic_lab/` | 可复现的三类本地教学实验 |
| `tests/test_logic_*.py` | 核心判断、管线契约、安全边界与实验测试 |
