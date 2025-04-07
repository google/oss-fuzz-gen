#!/bin/bash
find . -name "*.c" -exec $CC $CFLAGS -I./src -c {} \;
find . -name "*.o" -exec cp {} . \;

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o


for fuzzer in $SRC/fuzzers/*; do
  fuzzer_target=$(basename $fuzzer)
  fuzzer_target="${fuzzer_target%.*}"
  $CC $CFLAGS $LIB_FUZZING_ENGINE ${fuzzer} -Wl,--whole-archive $SRC/sqlite-createtable-parser/libfuzz.a -Wl,--allow-multiple-definition -I$SRC/sqlite-createtable-parser/debug -I$SRC/sqlite-createtable-parser -o $OUT/${fuzzer_target}
done