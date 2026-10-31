# 暴风星云裂最终版正确样本 POC 动态验证

验证时间：2026-10-31  
目标：本机隔离 DVWA 靶场，经 `127.0.0.1:18081` 适配层转发到 `127.0.0.1:18080`。适配层只转换样本编号路径和 DVWA 必需字段，不执行 POC Shell。

## 结果

最终版 39 个正确样本中，37 个样本包含可解析的 HTTP POC，共 75 个 POC 被回放：

| 动态结果 | 数量 |
|---|---:|
| verified | 10 |
| rejected | 50 |
| inconclusive | 15 |
| error | 0 |
| 静态-only、没有可执行 HTTP POC | 2（017、018） |

`verified` 不能直接按样本数解释。10 个 verified 中：

- 与正确样本类别直接对应：`025/026/027` 命令注入、`028/030` 路径穿越、`052/054` 反射型 XSS，共 7 个样本。
- `019/020/021` 的 verified 是这些样本内额外的 XSS POC；它们的正确类别是 CSP，CSP POC 本身没有得到动态确认。

## 正确样本覆盖

| 样本 | 正确类别的动态结果 |
|---|---|
| 002 | rejected |
| 008 | inconclusive / rejected（SQL 注入与 IDOR 均未形成可信动态证据） |
| 011 | inconclusive / rejected |
| 012 | inconclusive / rejected |
| 013 | inconclusive / rejected |
| 014 | inconclusive / rejected |
| 015 | inconclusive / rejected |
| 016 | rejected；弱加密本身为静态-only |
| 017 | 静态-only，未执行 |
| 018 | 静态-only，未执行 |
| 019/020/021 | CSP POC rejected；额外 XSS POC verified |
| 023/024 | inconclusive / rejected |
| 025/026/027 | verified，响应包含 `uid=33(www-data)` |
| 028/030 | verified，响应出现路径穿越/文件包含警告差异 |
| 031/033 | rejected |
| 034/035/036 | rejected |
| 037/038/039 | inconclusive，SQL 注入无可观测错误或结果集差异 |
| 041/042 | inconclusive，SQL 注入无可观测错误或结果集差异 |
| 043/044/045 | rejected；上传 POC 未形成可执行 multipart 证据 |
| 046/047/048 | rejected；弱 ID 属于静态证据 |
| 052/054 | verified，响应反射未编码 `<script>alert(document.domain)</script>` |
| 053 | rejected |

## 解释边界

- `verified` 表示在隔离靶场中观察到类别特征响应，不等于原始样本的源码路径与生产环境完全一致。
- `inconclusive` 主要是盲注或缺少类别特有响应标记，不能作为漏洞成立或不存在的证据。
- `rejected` 表示本次请求在该靶场上没有得到可信差异；其中一部分 POC 的路径、参数或字段与 DVWA 接口不匹配。
- 弱加密、弱随机、弱 ID、弱哈希等没有单请求 HTTP 可观测量，仍需静态审查或专门的状态/算法测试。
- 适配层只监听 localhost；验证器不执行 Shell、不写目标文件、不访问外部主机。

原始机器结果：`aggregate/verification-batch.json`、`aggregate/verification-batch.md`、各样本目录下的 `verification/`。适配器日志在 `落日二号乙-ver3/tools/baofeng_dvwa_adapter.log`。
