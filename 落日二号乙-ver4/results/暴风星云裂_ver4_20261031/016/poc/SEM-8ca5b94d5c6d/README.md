# POC — 016.php 令牌生成调用 create_token() 的弱加密/可预测令牌风险（CWE-327）

- finding_id: `SEM-8ca5b94d5c6d`
- type: `weak_crypto` / CWE-327
- severity: `medium`
- file: `016.php:7`

## 步骤

1. **在源码中定位证据**  
```http
grep -n -A2 -B2 '<evidence>' 016.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**  
```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。