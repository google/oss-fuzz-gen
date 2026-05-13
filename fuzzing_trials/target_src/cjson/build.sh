#!/bin/bash -eu

# This script is meant to be run by
# https://github.com/google/oss-fuzz/blob/master/projects/cjson/Dockerfile

mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_CJSON_TEST=OFF ..
make -j$(nproc)

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

$CXX $CXXFLAGS /src/synthesized_driver/*.c* -I. -I..\
    -o $OUT/cjson_read_fuzzer \
    $SRC/cjson/build/libcjson.a

cp $OUT/cjson_read_fuzzer $OUT/fuzz_driver_$SANITIZER

find $SRC/cjson/fuzzing/inputs -name "*" | \
     xargs zip $OUT/cjson_read_fuzzer_seed_corpus.zip

cp $SRC/cjson/fuzzing/json.dict $OUT/cjson_read_fuzzer.dict