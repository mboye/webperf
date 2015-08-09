#!/bin/bash
set -u

failed=0

LOG_DIR="${BUILD_DIR}/webperf/ft"
mkdir -p "${LOG_DIR}"

for test in webperf/ft/cases/*
do
    if [ ! -f "${test}/test.sh" ]
    then
        echo "Warning: skipping ${test} because ${test}/test.sh does not exist." 1>&2
        continue
    fi

    test_name=$(basename $test)
    test_log="${LOG_DIR}/${test_name}.log"
    "${test}/test.sh" > "${test_log}"  2>&1

    rc=$?
    if [ "$rc" -eq 0 ]
    then
        echo "PASSED: ${test_name}"
    else
        echo "FAILED: ${test_name}, log file: ${test_log}"
        failed=1
    fi
done

exit $failed
