# 隐性逻辑漏洞最小对照实验

这是勇旭模块的可复现实验材料。所有实验仅在本机 127.0.0.1 的随机端口运行，不需要 API Key、第三方包、PHP 或数据库；不会读取 .env。

## 实验对象

- vulnerable.py：故意缺少服务端前置验证、信任客户端验证标记、缺少订单归属检查、缺少正数数量限制。
- fixed.py：添加对应服务端检查。验证码状态保存在服务端会话中，修改密码后消耗该状态。
- missing_context.py：模拟缺失中间件源码，专门测试“证据不足”；不导入也不执行。
- server.py：HTTP 服务实际调用上面 vulnerable.py / fixed.py 中被静态分析的函数。
- policies.json：由审计者提供的明确业务规则。该文件留在源码 ZIP 之外，避免受审项目自行声明“已经安全”。
- run_experiment.py：执行静态判定、32 组 HTTP 请求及状态对照，保存报告和源码 SHA-256。

HTTP 服务使用测试会话 alice-demo / bob-demo 代表两个用户，验证码答案 demo-ok 只是确定性测试桩。实验检查的是服务端业务约束，不验证真实验证码算法或生产登录系统。

## 运行

在“VulnCatcher-ver5”目录中执行：

    python -m examples.logic_lab.run_experiment --out docs/experiments/logic_20261101
    python -m unittest discover -s tests -p test_logic_lab.py -v

前者产生 experiment.json、experiment.md 和 logic_lab_sources.zip。记录中同时包含原始 014.php / 015.php 的静态分析结果，明确标注未对这两个 PHP 样本做动态验证。后者检查检测结果和实际服务端状态。

使用主流程检测同一份源码包：

    python -m sunset scan docs/experiments/logic_20261101/logic_lab_sources.zip --llm off --logic-policy examples/logic_lab/policies.json --out sunset-results/logic-lab-pipeline

注意主程序原有配置机制会读取环境设置；如果只想完全离线、不加载 .env，使用实验 runner，或直接构造 Settings(llm_mode="off") 调用 run_pipeline。实验 runner 不使用主程序的配置加载器。

## 如何判定实验通过

- 静态：漏洞版 4 条 candidate，修复版 4 条 guarded，缺上下文 3 条 needs_context。guarded 只说明当前规则在支持语法范围内得到满足，不代表整个应用安全。
- 动态：16 个场景分别在漏洞版、修复版执行，共 32 组。逐项比对密码、订单、余额和购买记录的完整前后状态，并检查 HTTP 响应一致性。
- 既检查攻击被阻止，也检查正常验证码流程、自有订单修改、正数购买仍能完成。
- 额外检查验证码重放、会话间隔离、伪造客户端身份、零数量、错误类型及无效会话。

样本为自行编写的最小复现。流程缺陷参考仓库 014.php / 015.php，但实验结果不能替代完整 DVWA 的部署和验证。订单与购买样本也是教学构造；不是宣称仓库其他项目具有这些漏洞。不存在“所有业务系统均已验证”的结论。