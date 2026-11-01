#!/usr/bin/env sh
set -eu
# Authorized testing only. Replace TARGET after review.
curl -sS -i -X POST 'http://TARGET:8080/045.php' \
  -H 'User-Agent: Sunset-AWVS-Probe/2.0' \
  -H 'Accept: */*' \
  -H 'Content-Type: multipart/form-data; boundary=----SunsetAWVSProbeBoundary' \
  --data-binary '------SunsetAWVSProbeBoundary
Content-Disposition: form-data; name="uploaded"; filename="sunset.txt"
Content-Type: text/plain

SUNSET_SAFE_UPLOAD
------SunsetAWVSProbeBoundary--'
