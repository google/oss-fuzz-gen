#!/bin/bash
find . -name "*.c" -exec $CC $CFLAGS -I./src -c {} \;
find . -name "*.o" -exec cp {} . \;

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o


for fuzzer in $SRC/fuzzers/*; do
  fuzzer_target=$(basename $fuzzer)
  fuzzer_target="${fuzzer_target%.*}"
  $CC $CFLAGS $LIB_FUZZING_ENGINE ${fuzzer} -Wl,--whole-archive $SRC/lorawan-parser/libfuzz.a -Wl,--allow-multiple-definition -I$SRC/lorawan-parser/util/parser -I$SRC/lorawan-parser/lib/libloragw/inc -I$SRC/lorawan-parser/lw -I$SRC/lorawan-parser/lib -o $OUT/${fuzzer_target}
done