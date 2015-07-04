#!/bin/bash
set -e

source "$(git rev-parse --show-toplevel)/webperf/ft/common/ft.bash"

failed=0

for test in $FT/test_*
do
    if [ ! -d "$test" ]
    then
        continue
    fi
    test_name=$(basename $test | cut -b6-)
    echo "Running test: $test_name"
    cd "$test" && "$test/test.sh"
    [ $? -ne 0 ] && echo "$test failed." && failed=1
done

exit $failed
