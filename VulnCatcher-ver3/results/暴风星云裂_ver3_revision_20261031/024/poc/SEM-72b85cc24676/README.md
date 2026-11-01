# POC — 024.php 口令修改流程缺少速率限制与失败锁定（CWE-307）

- finding_id: `SEM-72b85cc24676`
- type: `brute_force` / CWE-307
- severity: `high`
- file: `024.php:7`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/024'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 暴力破解防护缺失 载荷**  
```http
curl -sS -i -X ANY 'http://TARGET:8080/024?login/password=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。