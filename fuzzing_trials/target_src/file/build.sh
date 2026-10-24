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

autoreconf -i
./configure --enable-static --enable-fsect-man5
make V=1 all

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

$CXX $CXXFLAGS -std=c++11 -Isrc/ \
     /src/synthesized_driver/*.c* -o $OUT/magic_fuzzer_loaddb \
     ./src/.libs/libmagic.a -l:libz.a -l:liblz4.a -l:libbz2.a -l:liblzma.a -l:libzstd.a

cp $OUT/magic_fuzzer_loaddb $OUT/fuzz_driver_$SANITIZER

cp ./magic/magic.mgc $OUT/
mkdir -p /usr/local/share/misc
cp ./magic/magic.mgc /usr/local/share/misc/

mkdir pocs_all
find $SRC/pocs/ -type f -print0 | xargs -0 -I % mv -f % ./pocs_all

zip -j $OUT/magic_fuzzer_seed_corpus.zip ./tests/*.testfile $SRC/binary-samples/{elf,pe}-* $SRC/pocs_all

cp $OUT/magic_fuzzer_seed_corpus.zip $OUT/magic_fuzzer_loaddb_seed_corpus.zip 
