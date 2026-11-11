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
autoconf
autoheader
export LDFLAGS="$CFLAGS"
./configure LIBS="-lz -lm -lbz2 -llzma -lcurl -lcrypto -lpthread"
make -j$(nproc) libhts.a bgzip htsfile tabix annot-tsv 

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi


$CC $CFLAGS -I. -I./htslib -I.. \
    -r /src/synthesized_driver/*.c \
    -o test/fuzz/hts_open_fuzzer.o

# build fuzzers
$CXX $CXXFLAGS -o "$OUT/hts_open_fuzzer" test/fuzz/hts_open_fuzzer.o \
libhts.a -Wl,--start-group -lz -lbz2 -llzma -lcurl -lidn2 -lnghttp2 \
-lrtmp -lssh -lpsl -lnettle -lgnutls -lgssapi_krb5 -lldap -llber \
-lbrotlidec -lcrypto -lpthread -ldl -lrt -Wl,--end-group

cp $OUT/hts_open_fuzzer $OUT/fuzz_driver_$SANITIZER

zip -j $OUT/hts_open_fuzzer_seed_corpus.zip test/*.sam test/*.fai test/*.fa test/*.bai  test/*.cram test/*.bam test/*.crai 
