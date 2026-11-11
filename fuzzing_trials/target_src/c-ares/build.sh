#!/bin/bash -eu
# Copyright 2016 Google Inc.
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

cd $SRC/googletest
mkdir build
cd build
cmake ..
make -j$(nproc)
make install

cd $SRC/c-ares

# Build the project.
./buildconf
./configure --enable-debug --enable-tests
make clean
make -j$(nproc) V=1 all

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

# Build the fuzzers.
$CC $CFLAGS -Iinclude -Isrc/lib -r /src/synthesized_driver/*.c* -o $WORK/ares-test-fuzz.o
$CXX $CFLAGS -std=c++11 $WORK/ares-test-fuzz.o \
    -o $OUT/ares_parse_reply_fuzzer \
    $SRC/c-ares/src/lib/.libs/libcares.a

# Store copies of the different drivers for later analysis
cp $OUT/ares_parse_reply_fuzzer $OUT/fuzz_driver_$SANITIZER

# Archive and copy to $OUT seed corpus if the build succeeded.
# Combine all seeds into target zip
zip -j $OUT/ares_parse_reply_fuzzer_seed_corpus.zip $SRC/c-ares/test/fuzzinput/* $SRC/c-ares/test/fuzznames/*
zip -j $OUT/ares_create_query_fuzzer_seed_corpus.zip \
    $SRC/c-ares/test/fuzznames/*
