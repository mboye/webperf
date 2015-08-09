#!/bin/bash
set -eu

source "${ROOT}/webperf/ft/common/ft.bash"

URL=https://www.google.com/ncr
TARGETS="${TMP}/google.com.urls"

update_urls "${URL}" "${TARGETS}"

CONF="${TMP}/webperf.conf"
cp "${TEST_DIR}/webperf.conf" "${CONF}"

echo "dns.loadCache=${FT_COMMON}/root_servers.cache" >> $CONF
echo "http.CAFile=${FT_COMMON}/ca-certs.pem" >> $CONF
echo "test.loadURLs=${TARGETS}" >> $CONF

$WEBPERF "${CONF}" "${TMP}/webperf.output" > "${TMP}/webperf.stdout" 2>"${TMP}/webperf.stderr"
echo "Webperf exited with code $?"

"${TEST_DIR}/verify-json-output.py" "${TMP}/webperf.output.json"
