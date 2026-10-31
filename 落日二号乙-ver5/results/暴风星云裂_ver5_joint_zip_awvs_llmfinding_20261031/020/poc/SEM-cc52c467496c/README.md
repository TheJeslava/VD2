# POC — 020.php 依赖客户端脚本加载，服务端缺少对应校验（CWE-602）

- finding_id: `SEM-cc52c467496c`
- type: `client_side_validation` / CWE-602
- severity: `high`
- file: `020.php:15`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/020'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 客户端校验绕过 载荷**  
```http
curl -sS -i -X POST 'http://TARGET:8080/020' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'include=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。