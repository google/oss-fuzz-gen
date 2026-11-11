#!/bin/bash
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
PARENT_DIR=$(dirname "$SCRIPT_DIR")

export ASAN_OPTIONS="detect_leaks=0"

source $PARENT_DIR/.venv/bin/activate
export CASR_PATH=$SCRIPT_DIR/tools/casr/target/release
export PATH=$CASR_PATH:$PATH