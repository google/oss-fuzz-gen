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

git checkout 8a07083d78dbb779fe449d6b1fc17ccfda733cf9

mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_TOOLS=OFF ..
make

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

static_pcre=($(find /src/pcre2 -name "libpcre2-8.a"))

for fuzzer in lyd_parse_mem_xml; do
  $CC $CFLAGS -o ${fuzzer}.o -r /src/synthesized_driver/*.c* -I./libyang -I./compat
  $CXX $CXXFLAGS ${fuzzer}.o -o $OUT/${fuzzer} \
    ./libyang.a ${static_pcre}
done

cp $OUT/lyd_parse_mem_xml $OUT/fuzz_driver_$SANITIZER

zip -j $OUT/lyd_parse_mem_xml_seed_corpus.zip $SRC/libyang/tests/modules/yang/*.yang $SRC/libyang/tests/yanglint/data/*.xml $SRC/libyang/tests/yangre/files/*.txt 

# Build test
mkdir $SRC/libyang/build-test
cd $SRC/libyang/build-test
cmake -DCMAKE_BUILD_TYPE=Debug ..
make

