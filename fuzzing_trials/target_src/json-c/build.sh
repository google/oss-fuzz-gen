#!/bin/bash -eu
# Copyright 2018 Google Inc.
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
mkdir json-c-build
cd json-c-build
cmake -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=ON ..
make -j$(nproc)
cd ..

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

cp $SRC/json-c/fuzz/*.dict $OUT/

$CXX $CXXFLAGS -std=c++17 -I$SRC/json-c -I$SRC -I$SRC/json-c/json-c-build \
        /src/synthesized_driver/*.c* -o $OUT/json_array_fuzzer \
        $SRC/json-c/json-c-build/libjson-c.a

cp $OUT/json_array_fuzzer $OUT/fuzz_driver_$SANITIZER

zip -j $OUT/json_array_fuzzer_fuzzer_seed_corpus.zip $SRC/json-c/tests/*.json

