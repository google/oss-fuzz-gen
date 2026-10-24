#!/bin/bash -eux

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

cp $SRC/ucl_add_string_fuzzer.options $OUT/

./autogen.sh --force && ./configure
make

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

$CC $CFLAGS -r /src/synthesized_driver/*.c* \
  -DHAVE_CONFIG_H -I./src -I./include src/.libs/libucl.a -I./ \
  -o $OUT/ucl_add_string_fuzzer.o

$CXX $CXXFLAGS $OUT/ucl_add_string_fuzzer.o -DHAVE_CONFIG_H -I./src -I./include src/.libs/libucl.a -I. -o $OUT/ucl_add_string_fuzzer

cp $OUT/ucl_add_string_fuzzer $OUT/fuzz_driver_$SANITIZER

zip -r $OUT/ucl_add_string_fuzzer_seed_corpus.zip $SRC/libucl/tests/basic
