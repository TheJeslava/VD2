# POC — 058_06.php 认证 Cookie 使用固定值且缺少安全属性（CWE-330/CWE-565）

- finding_id: `SEM-381e6544791c`
- type: `weak_id` / CWE-330
- severity: `high`
- file: `058_06.php:44`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/058_06'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **在保持同一会话的情况下第一次 POST，记录 Set-Cookie**  
```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/058_06' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**  
```http
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/058_06' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现连续递增/可预测序列

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。