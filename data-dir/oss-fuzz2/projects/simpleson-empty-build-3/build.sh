#!/bin/bash
mkdir fuzz-build
cd fuzz-build
cmake -DCMAKE_VERBOSE_MAKEFILE=ON -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_CXX_FLAGS="$CXXFLAGS" ../
sed -i 's/SHARED/STATIC/g' ../CMakeLists.txt
make V=1 || true

for fuzzer in $SRC/fuzzers/*; do
  fuzzer_target=$(basename $fuzzer)
  fuzzer_target="${fuzzer_target%.*}"
  $CXX $CXXFLAGS $LIB_FUZZING_ENGINE ${fuzzer} -Wl,--whole-archive $SRC/simpleson/fuzz-build/libsimpleson.a -Wl,--allow-multiple-definition -I$SRC/simpleson -o $OUT/${fuzzer_target}
done