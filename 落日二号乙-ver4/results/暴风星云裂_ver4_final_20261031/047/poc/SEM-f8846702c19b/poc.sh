#!/usr/bin/env sh
set -eu
# 仅限授权测试；替换 TARGET 后手动执行
cookie_jar="$(mktemp)"
trap 'rm -f "$cookie_jar"' EXIT HUP INT TERM
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/047' -H 'Content-Type: application/x-www-form-urlencoded'
curl -sS -i -b "${cookie_jar}" -c "${cookie_jar}" -X POST 'http://TARGET:8080/047' -H 'Content-Type: application/x-www-form-urlencoded'
