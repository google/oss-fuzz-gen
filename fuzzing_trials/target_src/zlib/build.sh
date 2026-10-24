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

if ! ./configure; then
    cat configure.log
    exit 1
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

$CC $CFLAGS -I. /src/synthesized_driver/*.c* -o $OUT/minigzip_fuzzer ./libz.a


zip $OUT/seed_corpus.zip *.*
ln -sf $OUT/seed_corpus.zip $OUT/minigzip_fuzzer_seed_corpus.zip

cp $OUT/minigzip_fuzzer $OUT/fuzz_driver_$SANITIZER

# for f in $(find $SRC -name '*_fuzzer.c'); do
#     b=$(basename -s .c $f)
#     $CC $CFLAGS -I. $f -c -o /tmp/$b.o
#     $CXX $CXXFLAGS -o $OUT/$b /tmp/$b.o -stdlib=libc++ $LIB_FUZZING_ENGINE ./libz.a
#     rm -f /tmp/$b.o
#     ln -sf $OUT/seed_corpus.zip $OUT/minigzip_fuzzer_seed_corpus.zip
# done
