#!/bin/bash
if [ -z "$WORKSPACE" ]
then
    echo "WORKSPACE not defined."
    exit 1
fi

cd $WORKSPACE

code_review=0
verified=-1

COMMENTS="$WORKSPACE/review-comments.txt"
BUILD_LOG_CLANG="$WORKSPACE/build-clang.log"
BUILD_LOG_GCC="$WORKSPACE/build-gcc.log"

git log -1

"$WORKSPACE/tools/gerrit/detect-trailing-whitespace.sh" > $COMMENTS
if [ $(cat $COMMENTS | wc -l) -ne 0 ]; then
    code_review=-1
fi

echo "Build log: $BUILD_LOG_CLANG"

build_clang() {
    make CC=clang CFLAGS="-Weverything -Wno-padded" DEBUG=yes clean all > $BUILD_LOG_CLANG 2>&1
}

build_gcc() {
    make CC=gcc CFLAGS="-Wextra" DEBUG=yes clean all > $BUILD_LOG_GCC 2>&1
}

if build_clang && build_gcc && $WORKSPACE/webperf/ft/run-all-tests.sh
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
