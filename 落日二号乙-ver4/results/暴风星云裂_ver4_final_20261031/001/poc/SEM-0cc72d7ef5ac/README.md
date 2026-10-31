# POC — 001.php 页面直接暴露 OpenAPI 文档链接（CWE-200 信息泄露，证据不足）

- finding_id: `SEM-0cc72d7ef5ac`
- type: `api_info_disclosure` / CWE-200
- severity: `high`
- file: `001.php:7`

## 步骤

1. **在源码中定位证据**  
```http
grep -n -A2 -B2 '<evidence>' 001.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**  
```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。