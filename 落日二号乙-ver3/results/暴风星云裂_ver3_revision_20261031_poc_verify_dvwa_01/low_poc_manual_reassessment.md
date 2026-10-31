# low 样本类型匹配 POC 人工复核

复核对象：最终版中 **low 且检测类型与金标类别相匹配** 的样本。自动结果来自本轮 DVWA 隔离靶场回放；手工结论只回答当前 POC 是否足以验证对应漏洞，不把源码存在漏洞等同于动态确认。

结论分级：

- **可验证**：当前 POC 的请求和证据标准基本正确，自动判据需要补充相应字段/响应头判断。
- **部分可验证**：已经触及正确端点或汇点，但缺少触发条件、对照请求、浏览器执行或第二次请求，不能单独下动态结论。
- **不可验证**：当前 POC 的方法、参数、路径、请求格式或测试次数与源码触发条件不一致；修正后才可验证。
- **静态-only**：漏洞属于算法/实现属性，不能由单次 HTTP POC 证明。

| 样本 | 金标类别 / 匹配类型 | 自动结果 | 手工结论 | 依据与判定动作 |
|---|---|---|---|---|
| 002 | API 信息泄露 / `api_info_disclosure` | rejected | 部分可验证 | `002.php:47-49` 页面脚本会无认证 fetch `/vulnerabilities/api/v2/user/`，该接口在靶场实际返回用户对象。当前 curl POC 只比较 `/002` 的 HTML，既不执行浏览器 JS，参数名也不是源码中的控制点；需在浏览器执行页面或直接请求 API，并记录用户 JSON，不能仅凭当前差异判据确认。 |
| 008 | 越权 / `idor` | rejected（IDOR）；SQL POC inconclusive | 部分可验证 | 源码 `008.php:15-46` 要求同时提供 `action`、`user_id`，并用可篡改的 `user_id` Cookie 作授权判断。当前 POC 只发 Cookie，适配器替它补了查询参数且让 Cookie 与目标 ID 相同，未形成“用户 A 读取用户 B”的对照。应保持攻击者会话，分别请求自己的 ID 与另一用户 ID，确认返回另一用户资料。 |
| 011 | 暴力破解防护缺失 / `brute_force` | rejected | 不可验证 | 当前 POC 只发一次错误参数 `login/password`；源码 `011.php:3-9` 实际要求 `Login`、`username`、`password`。暴力破解需要连续多次登录并观察无锁定、无延迟、无限速，单请求不能证明。 |
| 014 | 验证码绕过 / `captcha_bypass` | rejected | 不可验证 | 绕过路径在 `014.php:3-14` 与 `45-57`：需要 POST `Change=Change`、`step=2`、两次密码字段，并在已认证会话中观察密码确实被更新。当前 POC 用查询参数 `captcha/step`，缺少 POST、`Change` 和密码字段；另一个 POC 路径含文本后缀，均未命中状态机。 |
| 017 | 弱加密 / `weak_crypto` | 静态-only | 静态-only | `017.php:3-14` 使用可逆、固定密钥 XOR（`wachtwoord`），这是实现属性。当前 POC 明确是离线源码审查，没有可执行 HTTP 请求；应以算法、密钥复用和可解密证据判定。 |
| 020 | CSP 配置缺陷 / `csp` | rejected（同样本 XSS POC verified） | 可验证 | `020.php:3` 的响应头直接包含过宽的 `script-src` 白名单；本轮攻击与基线的 CSP 头完全相同，所以“无差异”不是否定证据。读取基线 `Content-Security-Policy` 并检查允许的外部源即可验证，必要时再用 POST `include` 证明脚本注入影响。 |
| 023 | CSRF / `csrf` | rejected；SQL POC inconclusive | 不可验证 | 源码 `023.php:3-12` 的状态改变要求 GET `Change`、`password_new`、`password_conf`，且无 CSRF token。当前 POC 只发 `password_new` 或错误的参数名，没有触发更新；应在登录会话中用跨站请求发送完整字段，随后验证密码状态改变。 |
| 026 | OS 命令注入 / `command_injection` | verified（适配器补字段） | 部分可验证 | `026.php:3-14` 要求 POST `Submit` 后将 `ip` 拼入 `shell_exec`。本轮靶场因适配器自动追加 `Submit=Submit`，观察到 `uid=33(www-data)`；原始 POC 自身只提交 `ip=%3Bid`，单独运行不会进入分支，因此应把 `Submit=Submit` 写入 POC 后再认定为完整可验证。 |
| 035 | 开放重定向 / `open_redirect` | rejected | 可验证 | `035.php:3-4` 直接把 GET `redirect` 放入 `Location`。当前 DVWA 适配路由把它转成了不同接口并返回 200，导致通用判据误判；针对原始样本用 `curl -i` 且不跟随跳转，检查 `3xx` 和 `Location: //example.com` 即可验证。 |
| 038 | 盲 SQL 注入 / `sql_injection` | inconclusive | 部分可验证 | `038.php:3-5,11` 的 `id` 进入 SQL，但必须带 `Submit` 才执行。适配器补了该字段，当前单个 tautology 没有错误或结果差异；应发送成对的 true/false 条件或时间盲注，并比较状态、响应内容或延迟。源码与入口正确，现有一次请求不足以确认。 |
| 041 | SQL 注入 / `sql_injection` | inconclusive | 部分可验证 | `041.php:3-5,10` 同样要求 `Submit`，且查询结果回显在 `20` 行。当前 POC 缺 `Submit`，适配器补字段后仍只做一次 tautology；应补触发字段并用已知存在/不存在 ID 的成对查询比较回显或 SQL 错误。 |
| 044 | 不安全文件上传 / `file_upload` | rejected | 不可验证 | `044.php:3,9` 要求 POST 字段 `Upload`，并接收 multipart `uploaded` 后直接落盘。当前 `-F` 工件未被收集器解析，且 POC 也漏了 `Upload=Upload`；应发送真实 multipart，确认响应成功和上传文件存在，再判断扩展名/内容校验缺失。 |
| 047 | 弱会话 ID / `weak_id` | rejected | 原始 POC 不可验证；修正版实测确认 | 原始 GET 基线和 `?session cookie=SUNSET_PROBE` 攻击请求均为 200、3907 字节，未收到 `dvwaSession`，确实未触发 `047.php:6-11` 的 POST 分支。保持同一会话连续 POST 后实际收到 `dvwaSession=1、2、3、4`，确认会话 ID 可预测；漏洞成立，但原始 POC 需要改为重复 POST 并比较 Cookie。 |
| 053 | 反射型 XSS / `xss` | rejected | 不可验证 | 源码 `053.php:6-8` 的真实参数名是 `name`，并直接拼入 HTML。当前 POC 使用 `request parameter`，所以响应不反射 payload；改为 `?name=<script>alert(document.domain)</script>` 后检查未编码反射，必要时在浏览器确认执行。 |

## 汇总

14 个 low 匹配样本中：**可验证 2 个（020、035）**，**部分可验证 5 个（002、008、026、038、041）**，**当前 POC 不可验证 6 个（011、014、023、044、047、053）**，**静态-only 1 个（017）**。

因此，自动 rejected 中至少有 `002`、`020`、`035` 的判据偏严或证据提取不完整；`008`、`026`、`038`、`041` 主要是适配器补字段后才触发，不能把适配器行为当成原始 POC 已正确。其余 rejected 的主要问题是 POC 本身未满足源码触发条件，而不是验证器漏掉了一个已经完成的动态证明。

证据文件：`aggregate/verification-batch.json`、各样本目录下的 `verification/verification.json`，以及原始源码目录 `暴风星云裂/<样本>.php`。
