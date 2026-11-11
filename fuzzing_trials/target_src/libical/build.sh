#!/bin/bash -eu
# Copyright 2023 Google LLC
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

cmake . -DSTATIC_ONLY=ON -DLIBICAL_GLIB=False -DLIBICAL_GLIB_BUILD_DOCS=False -DLIBICAL_GOBJECT_INTROSPECTION=False -DLIBICAL_JAVA_BINDINGS=False -DLIBICAL_BUILD_TESTING=True
make install -j$(nproc)

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

$CXX $CXXFLAGS -std=c++11 /src/synthesized_driver/*.c* /usr/local/lib/libical.a -o $OUT/libical_fuzzer -I$SRC/libical/src/libical/

cp $OUT/libical_fuzzer $OUT/fuzz_driver_$SANITIZER

find . -name '*.ics' | xargs zip -q $OUT/libical_fuzzer_seed_corpus.zip
