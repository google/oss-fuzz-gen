#!/bin/bash -eu
#
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

if [[ "$SANITIZER" != "coverage" && "$SANITIZER" != "introspector" ]]
then
  ./autogen.sh --without-cython --enable-debug
else
  ./autogen.sh --without-cython --enable-debug --without-tests
fi
make -j$(nproc) clean
make -j$(nproc) all

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

for fuzzer in jplist_fuzzer; do
  $CXX $CXXFLAGS -Iinclude/ -Iinclude/plist \
      /src/synthesized_driver/*.c* -o $OUT/$fuzzer \
      src/.libs/libplist-2.0.a
done

cp $OUT/jplist_fuzzer $OUT/fuzz_driver_$SANITIZER

zip -j $OUT/bplist_fuzzer_seed_corpus.zip test/data/*.bplist
zip -j $OUT/xplist_fuzzer_seed_corpus.zip test/data/*.plist
zip -j $OUT/oplist_fuzzer_seed_corpus.zip test/data/*.ostep

# combine all corpus files for target
zip -j $OUT/jplist_fuzzer_seed_corpus.zip test/data/*.json test/data/*.ostep test/data/*.plist test/data/*.bplist

cp fuzz/*.dict fuzz/*.options $OUT/
