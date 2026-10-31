#!/usr/bin/env sh
set -eu
# Authorized testing only. Replace TARGET after review.
curl -sS -i -X GET 'http://TARGET:8080/016.php?token=test' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*'
