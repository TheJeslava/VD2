# POC — 002.php 通过 REQUEST_URI 字符串替换构造路径，存在信息泄露/路径处理缺陷（CWE-200）

- finding_id: `SEM-05c645928db9`
- type: `api_info_disclosure` / CWE-200
- severity: `high`
- file: `002.php:10`

## 步骤

1. **在源码中定位证据**  
```http
grep -n -A2 -B2 '<evidence>' 002.php
```
预期：命中硬编码凭据/弱算法/弱随机数调用

2. **人工确认凭据有效性或算法使用场景**  
```http
（离线审查）
```
预期：确认凭据仍有效或算法保护敏感数据

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。