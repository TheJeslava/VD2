# POC — 018.php 使用 AES-128-ECB 解密会话令牌，可被字节翻转/块拼接伪造 admin 身份

- finding_id: `LLM-86c6c58e13d2`
- type: `weak_crypto` / CWE-327
- severity: `high`
- file: `018.php:32`

## 步骤

1. **在源码中定位证据**  
```http
grep -n -A2 -B2 '<evidence>' 018.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**  
```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。