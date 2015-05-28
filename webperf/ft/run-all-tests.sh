#!/bin/bash
set -x
set -e

source "$(git rev-parse --show-toplevel)/webperf/ft/common/ft.bash"

for test in $FT/test_*
do
    if [ ! -d "$test" ]
    then
        continue
    fi

    cd "$test" && "$test/test.sh"
done