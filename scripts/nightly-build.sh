#!/bin/bash
SCAN_BUILD_DIR=scan-build
SCAN_BUILD_LOG="${SCAN_BUILD_DIR}/scan-build.log"

rc=0

if ! tools/gerrit-check.sh
then
    rc=1
fi

echo "Running scan-build..."
mkdir -p "${SCAN_BUILD_DIR}"
if ! scan-build -o scan-build-report \
    --html-title "Webperf Project" \
    --use-cc=clang \
    --use-c++=clang \
    make DEBUG=yes \
        BUILD_DIR=scan-build > "${SCAN_BUILD_LOG}" 2>&1
then
    echo "error: scan-build exited with code $?"
    echo "log file: ${SCAN_BUILD_LOG}"
    rc=1
fi

exit $rc
