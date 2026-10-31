# POC — 016.php 前端 fetch 调用暴露 API 端点与用户对象（CWE-200）

- finding_id: `SEM-22bc26282629`
- type: `api_info_disclosure` / CWE-200
- severity: `high`
- file: `016.php:18`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/016'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 API 信息泄露 载荷**  
```http
curl -sS -i -X ANY 'http://TARGET:8080/016?API version/user object=SUNSET_PROBE'
```
预期：按漏洞类型观察相应的异常响应/副作用。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。