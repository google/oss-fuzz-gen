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

#!/bin/bash -eux
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

mkdir oss_fuzz_build
cd oss_fuzz_build
# We disable libcbor's default sanitizers since we'll be configuring them ourselves via CFLAGS.
cmake -D CMAKE_BUILD_TYPE=Debug \
      -D CMAKE_INSTALL_PREFIX="$WORK" \
      -D SANITIZE=OFF \
      -D CMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
      ..
make "-j$(nproc)"
make install

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

$CXX $CXXFLAGS -std=c++11 "-I$WORK/include" \
    /src/synthesized_driver/*.c* -o "$OUT/cbor_load_fuzzer" \
    src/libcbor.a

zip -j $OUT/cbor_load_fuzzer_seed_corpus.zip ./examples/data/* ./test/data/*

cp $OUT/cbor_load_fuzzer $OUT/fuzz_driver_$SANITIZER

