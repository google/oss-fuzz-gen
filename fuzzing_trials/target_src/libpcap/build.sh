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

cd libpcap
# build project
mkdir -p build && cd build
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_REMOTE=OFF -DCMAKE_BUILD_TYPE=Release ..
# Avoid building testprogs since the main methods expects certain symbols
cmake --build . --target pcap_static -- -j$(nproc)

if [ -n "${BASELINE_COV:-}" ]; then
  CFLAGS="$CFLAGS -DBASELINE_COV"
  CXXFLAGS="$CXXFLAGS -DBASELINE_COV"
fi

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

# build fuzz targets
for target in both
do
    $CC $CFLAGS -I.. -I/src/libpcap/pcap/ -r /src/synthesized_driver/*.c* -o fuzz_$target.o
    $CXX $CXXFLAGS fuzz_$target.o -o $OUT/fuzz_$target libpcap.a
done

cp $OUT/fuzz_both $OUT/fuzz_driver_$SANITIZER

# export other associated stuff
cd ..
cp testprogs/fuzz/fuzz_*.options $OUT/
# builds corpus
cd $SRC/tcpdump/
zip -r fuzz_pcap_seed_corpus.zip tests/
cp fuzz_pcap_seed_corpus.zip $OUT/
cd $SRC/libpcap/testprogs/BPF
mkdir corpus
ls *.txt | while read i; do tail -1 $i > corpus/$i; done
zip -r fuzz_filter_seed_corpus.zip corpus/
cp fuzz_filter_seed_corpus.zip $OUT/

# merged seed files
zip -r $OUT/fuzz_both_seed_corpus.zip tests/ corpus/
