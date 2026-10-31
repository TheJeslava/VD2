# 暴风星云裂最终联合结果与落日验证

- 金标判断正确样本：50/58（仅这些样本执行 POC 验证）
- 验证 POC：90；verified=24，rejected=42，inconclusive=24，unsupported=0，error=0
- 与金标类别一致的 verified POC：22，样本：008, 009, 019, 020, 021, 025, 026, 027, 043, 044, 045, 046, 047, 048, 052, 053, 054

| 样本 | 金标类别 | POC | verified | rejected | inconclusive | 类别一致 verified |
|---|---|---:|---:|---:|---:|---:|
| 002 | api | 0 | 0 | 0 | 0 | 0 |
| 004 | authbypass | 1 | 0 | 1 | 0 | 0 |
| 005 | authbypass | 1 | 0 | 1 | 0 | 0 |
| 006 | authbypass | 1 | 0 | 1 | 0 | 0 |
| 008 | bac | 5 | 1 | 0 | 4 | 1 |
| 009 | bac | 4 | 1 | 0 | 3 | 1 |
| 011 | brute | 3 | 0 | 2 | 1 | 0 |
| 012 | brute | 3 | 0 | 2 | 1 | 0 |
| 013 | captcha | 3 | 0 | 2 | 1 | 0 |
| 014 | captcha | 5 | 0 | 4 | 1 | 0 |
| 015 | captcha | 5 | 0 | 4 | 1 | 0 |
| 016 | cryptography | 0 | 0 | 0 | 0 | 0 |
| 017 | cryptography | 0 | 0 | 0 | 0 | 0 |
| 018 | cryptography | 0 | 0 | 0 | 0 | 0 |
| 019 | csp | 3 | 1 | 2 | 0 | 1 |
| 020 | csp | 4 | 2 | 2 | 0 | 1 |
| 021 | csp | 3 | 2 | 1 | 0 | 1 |
| 023 | csrf | 5 | 0 | 4 | 1 | 0 |
| 024 | csrf | 3 | 0 | 2 | 1 | 0 |
| 025 | exec | 3 | 2 | 1 | 0 | 2 |
| 026 | exec | 3 | 2 | 1 | 0 | 2 |
| 027 | exec | 2 | 2 | 0 | 0 | 2 |
| 028 | fi | 1 | 0 | 1 | 0 | 0 |
| 029 | fi | 1 | 0 | 1 | 0 | 0 |
| 030 | fi | 1 | 0 | 1 | 0 | 0 |
| 031 | javascript | 1 | 0 | 1 | 0 | 0 |
| 032 | javascript | 1 | 0 | 1 | 0 | 0 |
| 033 | javascript | 1 | 0 | 1 | 0 | 0 |
| 034 | open_redirect | 1 | 0 | 0 | 1 | 0 |
| 035 | open_redirect | 1 | 0 | 0 | 1 | 0 |
| 036 | open_redirect | 1 | 0 | 0 | 1 | 0 |
| 037 | sqli_blind | 1 | 0 | 0 | 1 | 0 |
| 038 | sqli_blind | 1 | 0 | 0 | 1 | 0 |
| 039 | sqli_blind | 1 | 0 | 0 | 1 | 0 |
| 040 | sqli | 1 | 0 | 0 | 1 | 0 |
| 041 | sqli | 1 | 0 | 0 | 1 | 0 |
| 042 | sqli | 1 | 0 | 0 | 1 | 0 |
| 043 | upload | 2 | 1 | 1 | 0 | 1 |
| 044 | upload | 2 | 2 | 0 | 0 | 2 |
| 045 | upload | 2 | 2 | 0 | 0 | 2 |
| 046 | weak_id | 1 | 1 | 0 | 0 | 1 |
| 047 | weak_id | 1 | 1 | 0 | 0 | 1 |
| 048 | weak_id | 1 | 1 | 0 | 0 | 1 |
| 049 | xss_d | 1 | 0 | 1 | 0 | 0 |
| 050 | xss_d | 1 | 0 | 1 | 0 | 0 |
| 051 | xss_d | 2 | 0 | 2 | 0 | 0 |
| 052 | xss_r | 1 | 1 | 0 | 0 | 1 |
| 053 | xss_r | 1 | 1 | 0 | 0 | 1 |
| 054 | xss_r | 1 | 1 | 0 | 0 | 1 |
| 057 | xss_s | 2 | 0 | 1 | 1 | 0 |

## 限制

- URL target was the local 127.0.0.1:18081 AWVS-compatible DVWA adapter.
- The adapter maps sample paths to DVWA category routes; it is not a deployment of every original PHP sample.
- 058 uses a DVWA SQLi fallback and is excluded because its gold hit is false/partial.
- verified means response evidence matched the verifier marker; matching_verified additionally requires the gold category.
