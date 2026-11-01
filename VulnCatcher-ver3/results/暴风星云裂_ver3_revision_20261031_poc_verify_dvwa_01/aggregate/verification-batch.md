# 落日验证报告

- 生成时间：2026-10-31T02:58:29.842925+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：``

## 汇总

- 总数：75
- verified：10
- rejected：50
- inconclusive：15
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `GEN-3b547dba7a60` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `SEM-536ee862bb25` | `brute_force` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-c969ca7950b6` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `SEM-bb3630458a80` | `brute_force` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-996252269452` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `SEM-05c645928db9` | `api_info_disclosure` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-89dab2f7ae60` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-a618508f9b61` | `auth_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-07d9d737e404` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-22bc26282629` | `api_info_disclosure` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-74a307a2a91c` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-ecdc7684a376` | `captcha_bypass` | **rejected** | 0.5 | 404 | 404 | no meaningful differential between baseline and attack |
| `SEM-161a1ab1f6bd` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-16d21f2078ab` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-c00a42452f04` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-c737fb0d7fd9` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-2b846713ecdc` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-1c448a06ff3b` | `weak_hash` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-bb70b3793387` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-f0aa8e8c7f6b` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-efda4d219748` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-31888d7d7e9c` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-207aeb80f46b` | `idor` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-e3f1dc6ea55d` | `weak_id` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-c0759cbfa182` | `path_traversal` | **rejected** | 0.6 | 200 | 200 | no traversal marker or path reflection observed |
| `SEM-99a2f26a9c57` | `client_side_validation` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-cf764c9b36ce` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `SEM-3004577a69c4` | `csp` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-8f1d6361cb1e` | `path_traversal` | **rejected** | 0.6 | 200 | 200 | no traversal marker or path reflection observed |
| `SEM-cc52c467496c` | `client_side_validation` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-370901c0cb4c` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `SEM-582e93de1b73` | `csp` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-1b352c5348d3` | `path_traversal` | **rejected** | 0.6 | 200 | 200 | no traversal marker or path reflection observed |
| `LLM-cd298cc9bb86` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `SEM-e8635bcf499d` | `csp` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-cf38b1a2cb95` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-3eef1cf779fd` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-72b85cc24676` | `brute_force` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-7bbc11033fc9` | `weak_hash` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-77434b11a59f` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `GEN-2da8a6e02c4e` | `command_injection` | **rejected** | 0.6 | 200 | 200 | no command output marker observed |
| `GEN-eff51e7cd060` | `command_injection` | **rejected** | 0.6 | 200 | 200 | no command output marker observed |
| `LLM-3ff09f0d6739` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `GEN-a86a53dc898b` | `command_injection` | **rejected** | 0.6 | 200 | 200 | no command output marker observed |
| `GEN-78a67b34378e` | `command_injection` | **rejected** | 0.6 | 200 | 200 | no command output marker observed |
| `LLM-49f2aa772ae4` | `path_traversal` | **verified** | 0.85 | 200 | 200 | traversal marker in attack response: '../' |
| `GEN-2fcabc51c287` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-fb8cc628a9b1` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-e5f2216eebb4` | `brute_force` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-a3511d5e69f7` | `weak_hash` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-b5cfc3d8dbaa` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-54805d73cd84` | `path_traversal` | **verified** | 0.85 | 200 | 200 | traversal marker in attack response: '../' |
| `SEM-27b732a5104d` | `client_side_validation` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-2ffadbadfdc4` | `client_side_validation` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-70df6c6c834b` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `GEN-2b40f95f1bb0` | `command_injection` | **rejected** | 0.6 | 200 | 200 | no command output marker observed |
| `LLM-b2053a861f4e` | `open_redirect` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-7af8cc31bcdd` | `open_redirect` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-86a3d201a6c6` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-5bc99d7a2891` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-17fe713500f4` | `open_redirect` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-22ffdf9a5620` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-65bf75938433` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-cee48d9ee314` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-729d053acdfd` | `file_upload` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-f8846702c19b` | `weak_id` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-7d549df94451` | `file_upload` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-6ccece6535f3` | `file_upload` | **rejected** | 0.5 | 404 | 404 | no meaningful differential between baseline and attack |
| `SEM-19354a0facf2` | `weak_id` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-60f80eecf7e1` | `file_upload` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-ba92d09576fd` | `file_upload` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-26658112c975` | `weak_id` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-04dd02aad740` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `LLM-4be6b4e0336a` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `SEM-fca2dd504a67` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。