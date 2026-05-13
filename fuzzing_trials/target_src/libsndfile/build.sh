#!/bin/bash -eu
# Copyright 2019 Google Inc.
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

# Run the OSS-Fuzz script in the project.
apt-get update
#!/bin/bash -eu

# This script is called by the oss-fuzz main project when compiling the fuzz
# targets. This script is regression tested by ci_oss.sh.

# Save off the current folder as the build root.
export BUILD_ROOT=$PWD

export MAKEFLAGS+="-j$(nproc)"

# Install dependencies
apt-get -y install autoconf autogen automake libtool pkg-config python

# Compile the fuzzer.
autoreconf -vif
./configure --disable-shared --enable-ossfuzzers
make V=1

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

$CXX $CXXFLAGS /src/synthesized_driver/*.c* -I./include \
    src/.libs/libsndfile.a \
    -o $OUT/sndfile_alt_fuzzer

cp $OUT/sndfile_alt_fuzzer $OUT/fuzz_driver_$SANITIZER

# To make CIFuzz fast, see here for details: https://github.com/libsndfile/libsndfile/pull/796
for fuzzer in sndfile_alt_fuzzer sndfile_fuzzer; do
  echo "[libfuzzer]" > ${OUT}/${fuzzer}.options
  echo "close_fd_mask = 3" >> ${OUT}/${fuzzer}.options
done

cp $SRC/seeds.zip $OUT/sndfile_alt_fuzzer_seed_corpus.zip 

