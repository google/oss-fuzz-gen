#!/bin/bash
for file in "tiny-json.c"; do
  $CC $CFLAGS -c ${file}
done

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o


for fuzzer in $SRC/fuzzers/*; do
  fuzzer_target=$(basename $fuzzer)
  fuzzer_target="${fuzzer_target%.*}"
  $CC $CFLAGS $LIB_FUZZING_ENGINE ${fuzzer} -Wl,--whole-archive $SRC/tiny-json/libfuzz.a -Wl,--allow-multiple-definition -I$SRC/tiny-json -o $OUT/${fuzzer_target}
done