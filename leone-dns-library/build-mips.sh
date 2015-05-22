#!/bin/bash

#Check if debugging has been enabled.
if [ $# -ne 1 ]; then
	echo "Missing CFLAGS parameter!"
	exit 1
fi
CFLAGS=$1
echo "CFLAGS=$CFLAGS"
OPENWRTDIR=/home/boyem1/leone/openwrt
STAGING_DIR=$OPENWRTDIR/trunk/staging_dir/
PATH=$STAGING_DIR/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33/usr/bin:$PATH 
PATH=$STAGING_DIR/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33/usr/lib:$PATH 
PATH=$STAGING_DIR/toolchain-mips_gcc-4.3.3+cs_uClibc-0.9.30.1/usr/mips-openwrt-linux-uclibc/bin:$PATH 
mips-openwrt-linux-uclibc-gcc \
-I/home/boyem1/leone/repo/leone-tools/  \
-I$STAGING_DIR/target-mips_r2_uClibc-0.9.33/usr/include/ \
-L$STAGING_DIR/toolchain-mips_r2_gcc-4.6-linaro_uClibc-0.9.33/lib \
-L$STAGING_DIR/target-mips_r2_uClibc-0.9.33/root-ar71xx/usr/lib \
-L/home/boyem1/leone/repo/leone-tools/mips/ \
$CFLAGS -shared -fPIC *.c -o mips/libleonedns.so -lleonetools -Wl,-rpath-link=$STAGING_DIR/target-mips_r2_uClibc-0.9.33/root-ar71xx/usr/lib ../leone-tools/mips/libleonetools.so
