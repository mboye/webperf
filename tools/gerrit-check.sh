#!/bin/bash
if [ -z "$WORKSPACE" ]
then
    echo "WORKSPACE not defined."
    exit 1
fi

cd $WORKSPACE

export GMOCK=/proj/webperf/gmock-1.7.0

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

make BUILD_DIR=ut_coverage_build ut_coverage

build_clang() {
    make CC=clang CFLAGS="-Weverything -Wno-padded" DEBUG=yes clean all > $BUILD_LOG 2>&1
    rc=$?
    [ $rc -ne 0 ] && echo "Build failed."
    return $rc
}

if build_clang && $WORKSPACE/webperf/ft/run-all-tests.sh
then
    verified=1
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
