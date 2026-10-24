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

# build project
sh autogen.sh
./configure
make -j$(nproc)

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

$CC $CFLAGS -I. -I./htp -r /src/synthesized_driver/*.c* -o fuzz_htp.o
$CXX $CXXFLAGS fuzz_htp.o -o $OUT/fuzz_htp_c ./htp/.libs/libhtp.a -lz -llzma

cp $OUT/fuzz_htp_c $OUT/fuzz_driver_$SANITIZER

# builds corpus
zip -r $OUT/fuzz_htp_seed_corpus.zip test/files/*.t
