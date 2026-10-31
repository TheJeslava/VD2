#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X GET 'http://TARGET:8080/009.php?user_id=2'
