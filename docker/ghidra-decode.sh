#!/bin/sh
set -eu
if [ $# -lt 1 ]; then
    echo "usage: ghidra-decode <binary> [processor]" >&2
    exit 2
fi
export JAVA_HOME=/opt/jdk21
PROJ=$(mktemp -d)
exec /opt/ghidra/support/analyzeHeadless "$PROJ" decode -overwrite \
    -import "$1" -processor "${2:-iRISC:BE:32:default}" \
    -preScript PreFunc.java -postScript Disasm.java
