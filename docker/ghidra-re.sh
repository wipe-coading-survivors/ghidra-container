#!/bin/sh
set -eu
if [ $# -lt 1 ]; then
    echo "usage: ghidra-re <import|script> ..." >&2
    exit 2
fi
export JAVA_HOME=/opt/jdk21
CMD=$1; shift
case "$CMD" in
    import)
        if [ $# -lt 2 ]; then
            echo "usage: ghidra-re import <binary> <project-dir> [processor] [prescript]" >&2
            exit 2
        fi
        BIN=$1; PROJ=$2; PROC=${3:-iRISC:BE:32:default}; PRE=${4:-PreFunc.java}
        mkdir -p "$PROJ"
        exec /opt/ghidra/support/analyzeHeadless "$PROJ" ghidra_re -overwrite \
            -import "$BIN" -processor "$PROC" \
            -preScript "$PRE" -postScript Disasm.java
        ;;
    script)
        if [ $# -lt 3 ]; then
            echo "usage: ghidra-re script <project-dir> <program-name> <script.java>" >&2
            exit 2
        fi
        PROJ=$1; PROG=$2; SCRIPT=$3
        exec /opt/ghidra/support/analyzeHeadless "$PROJ" ghidra_re \
            -process "$PROG" -postScript "$SCRIPT"
        ;;
    *)
        echo "unknown mode: $CMD" >&2
        exit 2
        ;;
esac
