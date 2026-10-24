#!/bin/bash

set -u
set -e

pushd $SRC/libjpeg-turbo.main
cmake . -DENABLE_STATIC=1 -DWITH_TURBOJPEG=1
make -j$(nproc) all
popd


if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

$CXX $CXXFLAGS -I$SRC/libjpeg-turbo.main/src/ -I$SRC/libjpeg-turbo.main/ \
    /src/synthesized_driver/*.c* \
    $SRC/libjpeg-turbo.main/libturbojpeg.a $SRC/libjpeg-turbo.main/libjpeg.a \
    -o $OUT/compress_fuzzer

cp $OUT/compress_fuzzer $OUT/fuzz_driver_$SANITIZER

for fuzzer in compress; do
	cp $SRC/compress_fuzzer_seed_corpus.zip $OUT/${fuzzer}_fuzzer_seed_corpus.zip
done