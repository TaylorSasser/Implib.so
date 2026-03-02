#!/bin/sh

# Copyright 2019-2025 Yury Gribov
#
# The MIT License (MIT)
# 
# Use of this source code is governed by MIT license that can be
# found in the LICENSE.txt file.

set -eu
# TODO: use pipefail here and in test scripts

if test -n "${TRAVIS:-}" -o -n "${GITHUB_ACTIONS:-}"; then
  set -x
fi

cd $(dirname $0)/..

ARCH=${ARCH:-}
export PYTHON="${PYTHON:-python3}"

LOG_DIR=$(mktemp -d)
trap 'rm -rf "$LOG_DIR"' EXIT

PID_LIST=""
run_test() {
  name=$1
  shift
  "$@" > "$LOG_DIR/$name.log" 2>&1 &

  pid=$!
  PID_LIST="$PID_LIST $pid"
  eval "NAME_$pid=\"$name\""
}

run_test "basic" tests/basic/run.sh $ARCH
run_test "exceptions" tests/exceptions/run.sh $ARCH
run_test "data-warnings" tests/data-warnings/run.sh $ARCH
run_test "vtables" tests/vtables/run.sh $ARCH

if test -z "$ARCH" && ! echo "${CC:-}" | grep -q musl-gcc; then
  run_test "ld" tests/ld/run.sh
fi

if ! echo "$ARCH" | grep -q 'i[0-9]86'; then
  run_test "multilib" tests/multilib/run.sh $ARCH
fi

run_test "hidden" tests/hidden/run.sh $ARCH
run_test "verbose" tests/verbose/run.sh $ARCH
run_test "no_dlopen" tests/no_dlopen/run.sh $ARCH

if ! echo "${CC:-}" | grep -q musl-gcc; then
  run_test "multiple-dlopens" tests/multiple-dlopens/run.sh $ARCH
  run_test "multiple-dlopens-2" tests/multiple-dlopens-2/run.sh $ARCH
  run_test "multiple-dlopens-3" tests/multiple-dlopens-3/run.sh $ARCH
fi

if ! echo "$ARCH" | grep -q powerpc; then
  run_test "many-functions" tests/many-functions/run.sh $ARCH
fi

run_test "stack-args" tests/stack-args/run.sh $ARCH

if ! echo "$ARCH" | grep -q 'powerpc\|mips\|riscv'; then
  run_test "vector-args" tests/vector-args/run.sh $ARCH
fi

run_test "thread" tests/thread/run.sh $ARCH
run_test "thread-2" tests/thread-2/run.sh $ARCH
run_test "def" tests/def/run.sh $ARCH


FAIL_COUNT=0

for pid in $PID_LIST; do
    eval "name=\$NAME_$pid"

    if wait "$pid"; then
        FAIL_COUNT=$((FAIL_COUNT))
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
    fi

    if [ -f "$LOG_DIR/$name.log" ]; then
        cat "$LOG_DIR/$name.log"
    fi
done

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo "----------------------------------------"
    echo "Testing failed! Total suites failed: $FAIL_COUNT"
    exit 1
fi

echo 'All tests passed'