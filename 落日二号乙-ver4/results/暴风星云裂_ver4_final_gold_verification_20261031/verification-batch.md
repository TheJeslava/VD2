# 落日验证报告

- 生成时间：2026-10-31T09:47:41.051967+00:00
- 模式：`zip`
- 目标基址：`http://127.0.0.1:18081`
- 结果目录：``

## 汇总

- 总数：81
- verified：25
- rejected：35
- inconclusive：21
- unsupported：0
- error：0

| finding | 类型 | 结论 | 置信度 | baseline | attack | 原因 |
|---|---|---|---|---|---|---|
| `GEN-f0aa8e8c7f6b` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-efda4d219748` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-31888d7d7e9c` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-be8d58eeb7fa` | `idor` | **verified** | 0.75 | 200 | 200 | object profile returned under attacker-controlled identifier; compare with same-user baseline |
| `LLM-f5edf35e32f8` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `SEM-e3f1dc6ea55d` | `weak_id` | **inconclusive** | 0.45 | 200 | 200 | no numeric session cookie observed; multi-request comparison required |
| `GEN-769728152047` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-1f0233ec126f` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-07807b8ead6b` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-7d804c24fe1b` | `idor` | **verified** | 0.75 | 200 | 200 | object profile returned under attacker-controlled identifier; compare with same-user baseline |
| `LLM-c969ca7950b6` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `SEM-bb3630458a80` | `brute_force` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-996252269452` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `GEN-3b547dba7a60` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `SEM-536ee862bb25` | `brute_force` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-a7383455f404` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `GEN-89dab2f7ae60` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-719de589f39a` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-07d9d737e404` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-043ac2d2fadc` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-4859b1539c1e` | `weak_hash` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-74a307a2a91c` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-b52a2b477f7b` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-161a1ab1f6bd` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-ecdc7684a376` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-16d21f2078ab` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-c00a42452f04` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-c737fb0d7fd9` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-2b846713ecdc` | `captcha_bypass` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-c00e4d64a190` | `weak_hash` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-bb70b3793387` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-c0759cbfa182` | `path_traversal` | **rejected** | 0.6 | 200 | 200 | no traversal marker or path reflection observed |
| `SEM-99a2f26a9c57` | `client_side_validation` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-3004577a69c4` | `csp` | **verified** | 0.8 | 200 | 200 | Content-Security-Policy script-src observed; policy must be reviewed for excessive trust |
| `GEN-8f1d6361cb1e` | `path_traversal` | **rejected** | 0.6 | 200 | 200 | no traversal marker or path reflection observed |
| `SEM-cc52c467496c` | `client_side_validation` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-370901c0cb4c` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `SEM-582e93de1b73` | `csp` | **verified** | 0.8 | 200 | 200 | Content-Security-Policy script-src observed; policy must be reviewed for excessive trust |
| `GEN-11054cd96202` | `path_traversal` | **rejected** | 0.6 | 200 | 200 | no traversal marker or path reflection observed |
| `LLM-cd298cc9bb86` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `SEM-e8635bcf499d` | `csp` | **verified** | 0.8 | 200 | 200 | Content-Security-Policy script-src observed; policy must be reviewed for excessive trust |
| `GEN-2fcabc51c287` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-fb8cc628a9b1` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-e5f2216eebb4` | `brute_force` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-3fa1c975a8fc` | `weak_hash` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-b5cfc3d8dbaa` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `GEN-cf38b1a2cb95` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-3eef1cf779fd` | `csrf` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-72b85cc24676` | `brute_force` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-7bbc11033fc9` | `weak_hash` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-229f7d2e8603` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `GEN-2da8a6e02c4e` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `LLM-709cbd914c63` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `GEN-a86a53dc898b` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `LLM-ee1cf990d74d` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `GEN-2b40f95f1bb0` | `command_injection` | **verified** | 0.9 | 200 | 200 | command output marker in attack response |
| `GEN-54805d73cd84` | `path_traversal` | **rejected** | 0.6 | 200 | 200 | no traversal marker or path reflection observed |
| `SEM-27b732a5104d` | `client_side_validation` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `SEM-2ffadbadfdc4` | `client_side_validation` | **rejected** | 0.5 | 200 | 200 | no meaningful differential between baseline and attack |
| `LLM-347c957364bd` | `open_redirect` | **rejected** | 0.6 | 200 | 200 | no redirect status and Location header observed |
| `LLM-5ea158bc397a` | `open_redirect` | **rejected** | 0.6 | 200 | 200 | no redirect status and Location header observed |
| `LLM-7af8cc31bcdd` | `open_redirect` | **rejected** | 0.6 | 200 | 200 | no redirect status and Location header observed |
| `GEN-86a3d201a6c6` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-5bc99d7a2891` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-22ffdf9a5620` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-b04dcf20e12f` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `LLM-0c0cfd9fd4a7` | `xss` | **rejected** | 0.6 | 200 | 200 | no unencoded script reflection observed |
| `GEN-cee48d9ee314` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-65bf75938433` | `sql_injection` | **inconclusive** | 0.45 | 200 | 200 | no SQL error or row-set change observed (possible blind injection) |
| `GEN-729d053acdfd` | `file_upload` | **verified** | 0.85 | 200 | 200 | multipart upload accepted and upload path disclosed |
| `LLM-7a70487f2fb0` | `file_upload` | **verified** | 0.85 | 200 | 200 | multipart upload accepted and upload path disclosed |
| `GEN-7d549df94451` | `file_upload` | **verified** | 0.85 | 200 | 200 | multipart upload accepted and upload path disclosed |
| `LLM-6ccece6535f3` | `file_upload` | **verified** | 0.85 | 200 | 200 | multipart upload accepted and upload path disclosed |
| `GEN-60f80eecf7e1` | `file_upload` | **verified** | 0.85 | 200 | 200 | multipart upload accepted and upload path disclosed |
| `LLM-916b10bd8caa` | `file_upload` | **verified** | 0.85 | 200 | 200 | multipart upload accepted and upload path disclosed |
| `SEM-19354a0facf2` | `weak_id` | **verified** | 0.9 | 200 | 200 | consecutive attack responses emitted numerically consecutive session identifiers |
| `SEM-f8846702c19b` | `weak_id` | **verified** | 0.9 | 200 | 200 | consecutive attack responses emitted numerically consecutive session identifiers |
| `SEM-26658112c975` | `weak_id` | **verified** | 0.9 | 200 | 200 | consecutive attack responses emitted numerically consecutive session identifiers |
| `LLM-4be6b4e0336a` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `SEM-fca2dd504a67` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |
| `LLM-04dd02aad740` | `xss` | **verified** | 0.9 | 200 | 200 | unencoded script payload reflected in attack response |

## 安全边界

- 仅执行解析出的 HTTP 请求，不执行 POC shell 脚本。
- 仅允许 localhost/127.0.0.1/::1 与显式 allowlist 主机。
- 验证结果中的 `executed=true` 仅表示本验证器执行了请求。