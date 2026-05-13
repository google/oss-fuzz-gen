#!/bin/bash -eu
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

mkdir build-dir && cd build-dir
cmake -DENABLE_ROARING_TESTS=ON ..
make -j$(nproc)

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi


$CC $CFLAGS  \
     -I$SRC/croaring/include -I$SRC/croaring/include/roaring \
     -r /src/synthesized_driver/*.c* -o fuzzer.o

$CXX $CXXFLAGS fuzzer.o   \
     -o $OUT/croaring_fuzzer $SRC/croaring/build-dir/src/libroaring.a

cp $OUT/croaring_fuzzer $OUT/fuzz_driver_$SANITIZER

zip $OUT/croaring_fuzzer_seed_corpus.zip $SRC/croaring/tests/testdata/*bin
cp $SRC/croaring/tests/testdata/*bin $OUT/