#!/bin/bash
touch empty_wrapper.c
# Write includes for each of the header files
echo "#include \"src/nanosvg.h\"" >> empty_wrapper.c
echo "#include \"src/nanosvgrast.h\"" >> empty_wrapper.c

rm -rf *.o
$CC $CFLAGS -c empty_wrapper.c -o empty_wrapper.o
llvm-ar rcs libfuzz.a *.o


for fuzzer in $SRC/fuzzers/*; do
  fuzzer_target=$(basename $fuzzer)
  fuzzer_target="${fuzzer_target%.*}"
  $CC $CFLAGS $LIB_FUZZING_ENGINE ${fuzzer} -Wl,--whole-archive $SRC/nanosvg/libfuzz.a -Wl,--allow-multiple-definition -I$SRC/nanosvg/src -I$SRC/nanosvg/example -o $OUT/${fuzzer_target}
done