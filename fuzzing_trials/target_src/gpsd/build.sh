#!/bin/bash -eu
# Copyright 2026 Google LLC
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
export CC="$CC $CFLAGS"
export CXX="$CXX $CFLAGS"
export CFLAGS=""
export CXXFLAGS="$CFLAGS"

# Build GPSD
scons

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

pushd fuzzer/
  DIR=$(ls -d ../gpsd*~dev/)
  INC="-I${DIR}include/"
  EXTCFLAGS="-pthread -std=c99"
  LibINC="-L${DIR}"
  LibFLAGS="-lgpsd -lgps_static -lm -lrt -lnsl" 

  # Remove -r and add LibINC/LibFLAGS
  $CC $CFLAGS $INC $EXTCFLAGS /src/synthesized_driver/*.c* $LibINC $LibFLAGS -o FuzzClient
popd

# Prepare and copy fuzzers and corpus to $OUT
for fuzzer in FuzzClient
do
  cp fuzzer/${fuzzer} $OUT/
  zip -r $OUT/${fuzzer}_seed_corpus.zip $SRC/gpsd/corp/*_seed_corpus/*
  # Copy dictionary if it exists
  if [ -f "fuzzer/${fuzzer}.dict" ]; then
    cp fuzzer/${fuzzer}.dict $OUT/
  fi
done

cp $OUT/FuzzClient $OUT/fuzz_driver_$SANITIZER

