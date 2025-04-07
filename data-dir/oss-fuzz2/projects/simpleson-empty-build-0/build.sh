#!/bin/bash
find . -name "*.cpp" -exec $CXX $CXXFLAGS -I./src -c {} \;
find . -name "*.o" -exec cp {} . \;

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o


for fuzzer in $SRC/fuzzers/*; do
  fuzzer_target=$(basename $fuzzer)
  fuzzer_target="${fuzzer_target%.*}"
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE ${fuzzer} -Wl,--whole-archive $SRC/simpleson/libfuzz.a -Wl,--allow-multiple-definition -I$SRC/simpleson -o $OUT/${fuzzer_target}
done