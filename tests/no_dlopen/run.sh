#!/bin/sh

# Copyright 2022-2024 Yury Gribov
#
# The MIT License (MIT)
# 
# Use of this source code is governed by MIT license that can be
# found in the LICENSE.txt file.

# This is a test for manual loading of destination library (--no-dlopen flag).
# Run it like
#   ./run.sh ARCH
# where ARCH stands for any supported arch (arm, x86_64, etc., see `implib-gen -h' for full list).
# Note that you may need to install qemu-user for respective platform
# (i386 also needs gcc-multilib).

set -eu

cd $(dirname $0)

if test -n "${1:-}"; then
  ARCH="$1"
fi

. ../common.sh

CFLAGS="-g -O2 $CFLAGS"

if uname | grep -q BSD; then
  # readelf does not have --dyn-syms on BSDs
  READELF=llvm-readelf
else
  READELF=readelf
fi

check_symbol() {
  FILE=$1
  SYM=$2
  EXPECT_PRESENT=$3
  if uname | grep -q Darwin; then
    # On Mac
    if [ "$EXPECT_PRESENT" = "1" ]; then
      nm -g "$FILE" | grep -q "_$SYM"
    else
      ! nm -g "$FILE" | grep -q "_$SYM"
    fi
  else
    # On Linux
    if [ "$EXPECT_PRESENT" = "1" ]; then
      $READELF -sW --dyn-syms "$FILE" | grep -q "GLOBAL.*$SYM"
    else
      ! $READELF -sW --dyn-syms "$FILE" | grep -q "GLOBAL.*$SYM"
    fi
  fi
}

# Build shlib to test against
$CC $CFLAGS -shared -fPIC interposed.c -o libinterposed.so

##########################
# Standalone executables #
##########################

# Prepare implib
${PYTHON:-} ../../implib-gen.py -q --target $TARGET --no-dlopen libinterposed.so

# Build app
$CC $CFLAGS main.c test.c libinterposed.so.tramp.S libinterposed.so.init.c $LIBS
check_symbol a.out foo 0

LD_LIBRARY_PATH=.:${LD_LIBRARY_PATH:-} DYLD_LIBRARY_PATH=.:${DYLD_LIBRARY_PATH:-} $INTERP ./a.out > a.out.log
diff test.ref a.out.log

#########################################
# Standalone executables (public shims) #
#########################################

# Prepare implib
${PYTHON:-} ../../implib-gen.py -q --target $TARGET --no-dlopen libinterposed.so

# Build app
$CC $CFLAGS -DIMPLIB_EXPORT_SHIMS main.c test.c libinterposed.so.tramp.S libinterposed.so.init.c $LIBS
check_symbol a.out foo 1

LD_LIBRARY_PATH=.:${LD_LIBRARY_PATH:-} DYLD_LIBRARY_PATH=.:${DYLD_LIBRARY_PATH:-} $INTERP ./a.out > a.out.log
diff test.ref a.out.log

##########
# Shlibs #
##########

# Prepare implib
${PYTHON:-} ../../implib-gen.py -q --target $TARGET --no-dlopen libinterposed.so

# Build shlib
$CC $CFLAGS -shared -fPIC shlib.c test.c libinterposed.so.tramp.S libinterposed.so.init.c $LIBS -o shlib.so
check_symbol shlib.so foo 0

# Build app
$CC $CFLAGS main.c shlib.so $LIBS

LD_LIBRARY_PATH=.:${LD_LIBRARY_PATH:-} DYLD_LIBRARY_PATH=.:${DYLD_LIBRARY_PATH:-} $INTERP ./a.out > a.out.log
diff test.ref a.out.log

#########################
# Shlibs (public shims) #
#########################

# Prepare implib
${PYTHON:-} ../../implib-gen.py -q --target $TARGET --no-dlopen libinterposed.so

# Build shlib
$CC $CFLAGS -DIMPLIB_EXPORT_SHIMS -shared -fPIC shlib.c test.c libinterposed.so.tramp.S libinterposed.so.init.c $LIBS -o shlib.so
check_symbol shlib.so foo 1

# Build app
$CC $CFLAGS main.c shlib.so $LIBS

LD_LIBRARY_PATH=.:${LD_LIBRARY_PATH:-} DYLD_LIBRARY_PATH=.:${DYLD_LIBRARY_PATH:-} $INTERP ./a.out > a.out.log
diff test.ref a.out.log

echo SUCCESS
