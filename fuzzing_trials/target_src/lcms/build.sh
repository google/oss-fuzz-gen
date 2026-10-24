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

# build the target.
./configure --enable-shared=no
make -j$(nproc) all

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi


$CC $CFLAGS -r -Iinclude \
    /src/synthesized_driver/*.c* -o $SRC/cms_profile_fuzzer.o
$CXX $CXXFLAGS \
    $SRC/cms_profile_fuzzer.o -o $OUT/cms_profile_fuzzer \
    src/.libs/liblcms2.a

cp $OUT/cms_profile_fuzzer $OUT/fuzz_driver_$SANITIZER

cp $SRC/*.dict $SRC/*.options $OUT/
cp $SRC/icc.dict $OUT/cms_transform_all_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_transform_extended_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_universal_transform_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_profile_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_postscript_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_virtual_profile_fuzzer.dict
cp $SRC/icc.dict $OUT/cms_md5_fuzzer.dict
cp $SRC/seed_corpus.zip $OUT/cms_profile_fuzzer_seed_corpus.zip