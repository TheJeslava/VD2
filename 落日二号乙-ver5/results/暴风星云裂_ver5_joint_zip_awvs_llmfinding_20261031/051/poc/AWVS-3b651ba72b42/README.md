# POC — AWVS: Cross-site Scripting (XSS)

- finding_id: `AWVS-3b651ba72b42`
- type: `xss` / CWE-79
- severity: `high`
- file: `:0`

## 步骤

1. **重放 AWVS 记录的请求**  
```http
GET /051.php HTTP/1.1
Host: TARGET


```
预期：复现 AWVS 报告中的问题

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。