#!/bin/bash
cd $WORKSPACE

code_review=0
verified=-1

COMMENTS="$WORKSPACE/review-comments.txt"
BUILD_LOG="$WORKSPACE/build.log"

git log -1

"$WORKSPACE/tools/gerrit/detect-trailing-whitespace.sh" > $COMMENTS
if [ $(cat $COMMENTS | wc -l) -ne 0 ]; then
    code_review=-1
fi

echo "Build log: $BUILD_LOG"

export CC=clang
export CFLAGS="-Weverything -Wno-padded"
if make webperf/webperf > $BUILD_LOG 2>&1 && $WORKSPACE/webperf/ft/run-all-tests.sh
then
    echo "Build successful."
    verified=1
else
    echo "Build failed."
fi

cppcheck --enable=all --inconclusive --xml --xml-version=2 */src */include 1>/dev/null 2> cppcheck.xml

export CODE_REVIEW=$code_review
export VERIFIED=$verified

cat $COMMENTS | $WORKSPACE/tools/gerrit/gerrit-post-review.py

if [ $verified -eq -1 ]
then
    exit 1
else
    exit 0
fi
