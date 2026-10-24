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

export CFLAGS="$CFLAGS -fPIC"
export CXXFLAGS="$CXXFLAGS -fPIC"

# build project
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=OFF -DENABLE_HDF5=OFF -DENABLE_DAP=OFF ..
make -j$(nproc)

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

# compile
$CC $CFLAGS /src/synthesized_driver/*.c* -I$SRC/netcdf-c/include \
    -o $OUT/fuzz_open \
    $SRC/netcdf-c/build/libnetcdf.a -lm


cp $OUT/fuzz_open $OUT/fuzz_driver_$SANITIZER

cp fuzz/fuzz* $OUT/
