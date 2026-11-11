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

# Run the OSS-Fuzz script in the curl-fuzzer project.

if [ "$SANITIZER" = "none" ]; then
  export CFLAGS="$CFLAGS -pthread  -ldl"
  export CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  export CFLAGS="$CFLAGS -O0"
  export CXXFLAGS="$CXXFLAGS -O0"
fi

cd /src/curl_fuzzer
./ossfuzz.sh

$CXX $CXXFLAGS -std=c++17 /src/synthesized_driver/*.c* -I$SRC/curl/include -I$SRC/curl/include/curl \
  -o $OUT/curl_fuzzer \
  $SRC/curl_fuzzer/build/curl-install/lib/libcurl.a \
  $SRC/curl_fuzzer/build/nghttp2/src/nghttp2_external-build/lib/libnghttp2.a \
  $SRC/curl_fuzzer/build/openssl/src/openssl_external/libssl.a \
  $SRC/curl_fuzzer/build/openssl-install/lib/libcrypto.a \
  $SRC/curl_fuzzer/build/openldap-install/lib/libldap.a \
  $SRC/curl_fuzzer/build/openldap-install/lib/liblber.a \
  $SRC/curl_fuzzer/build/libidn2-install/lib/libidn2.a \
  $SRC/curl_fuzzer/build/zlib-install/lib/libz.a \
  $SRC/curl_fuzzer/build/zstd-install/lib/libzstd.a \
  -Wl,--start-group \
  $SRC/curl_fuzzer/build/lpm-install/lib/libprotobuf-mutator.a \
  $SRC/curl_fuzzer/build/lpm/src/libprotobuf_mutator_external-build/external.protobuf/lib/libprotobuf.a \
  $SRC/curl_fuzzer/build/lpm/src/libprotobuf_mutator_external-build/external.protobuf/lib/libabsl_*.a \
  -Wl,--end-group


cp $OUT/curl_fuzzer $OUT/fuzz_driver_$SANITIZER

zip -r $OUT/fuzz_url_seed_corpus.zip  $SRC/curl_fuzzer/corpora/*


