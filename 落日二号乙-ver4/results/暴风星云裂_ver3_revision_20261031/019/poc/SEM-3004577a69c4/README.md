# POC — 019.php CSP 配置为 script-src 'self' 的语义命中（CWE-693）

- finding_id: `SEM-3004577a69c4`
- type: `csp` / CWE-693
- severity: `medium`
- file: `019.php:2`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/019'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 CSP 配置缺陷 载荷**  
```http
curl -sS -i -X ANY 'http://TARGET:8080/019?include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。