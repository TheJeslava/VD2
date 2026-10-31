# POC — 018.php 硬编码 AES 密钥 "ik ben een aardbei"

- finding_id: `LLM-a5c5a430e98b`
- type: `hardcoded_secret` / CWE-798
- severity: `medium`
- file: `018.php:10`

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