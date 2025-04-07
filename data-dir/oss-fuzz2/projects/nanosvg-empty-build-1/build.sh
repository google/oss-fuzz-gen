#!/bin/bash
mkdir fuzz-build
cd fuzz-build
cmake -DCMAKE_VERBOSE_MAKEFILE=ON ../
make V=1 || true

for fuzzer in $SRC/fuzzers/*; do
  fuzzer_target=$(basename $fuzzer)
  fuzzer_target="${fuzzer_target%.*}"
  $CC $CFLAGS $LIB_FUZZING_ENGINE ${fuzzer} -Wl,--whole-archive $SRC/nanosvg/fuzz-build/libnanosvgrast.a -Wl,--whole-archive $SRC/nanosvg/fuzz-build/libnanosvg.a -Wl,--allow-multiple-definition -I$SRC/nanosvg/example -I$SRC/nanosvg/src -o $OUT/${fuzzer_target}
done