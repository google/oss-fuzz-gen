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
./configure --static-build --extra-cflags="${CFLAGS}" --extra-ldflags="${CFLAGS}"
make

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

cp $SRC/seeds_p1.zip $SRC/seeds.zip
zip -u $SRC/seeds.zip -r $SRC/seeds_p2.zip

fuzzers=$(find $SRC/gpac/testsuite/oss-fuzzers -name "fuzz_m2ts_probe.c")
for f in $fuzzers; do

    fuzzerName=$(basename $f .c)
    echo "Building fuzzer $fuzzerName"

    $CC $CFLAGS -I./include -I./include/gpac -I./ -DGPAC_HAVE_CONFIG_H -r /src/synthesized_driver/*.c* -o $fuzzerName.o
    $CC $CFLAGS $fuzzerName.o -o $OUT/$fuzzerName \
      ./bin/gcc/libgpac_static.a \
      -lm -lz -lpthread -lssl -lcrypto -DGPAC_HAVE_CONFIG_H

    # combine all seeds into target zip
    cp $SRC/seeds.zip $OUT/${fuzzerName}_seed_corpus.zip
done

cp $OUT/fuzz_m2ts_probe $OUT/fuzz_driver_$SANITIZER
