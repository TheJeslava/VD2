#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
curl -sS -i -X ANY 'http://TARGET:8080/019?external JavaScript=SUNSET_PROBE'
