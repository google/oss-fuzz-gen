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
sed -i 's/main/main2/g' tests/fuzzing/fuzz_backtranslate.c && \
sed -i 's/main/main2/g' tests/fuzzing/fuzz_translate_generic.c && \
sed -i 's/LLVMFuzzerRunDriver(&argc/\/\/LLVMFuzzerRunDriver(&argc/g' tests/fuzzing/fuzz_backtranslate.c && \
sed -i 's/LLVMFuzzerRunDriver(&argc/\/\/LLVMFuzzerRunDriver(&argc/g' tests/fuzzing/fuzz_translate_generic.c

./autogen.sh
./configure
make -j$(nproc) V=1

if [ "$SANITIZER" = "none" ]; then
  CFLAGS="$CFLAGS -pthread  -ldl"
  CXXFLAGS="$CXXFLAGS -pthread  -ldl"
fi

if [ "$SANITIZER" = "address" ]; then
  CFLAGS="$CFLAGS -O0"
  CXXFLAGS="$CXXFLAGS -O0"
fi

cd tests/fuzzing
cp ../tables/empty.ctb $OUT/
find ../.. -name "*.o" -exec ar rcs fuzz_lib.a {} \;
cp -r /src/synthesized_driver /src/liblouis/tests/
$CXX $CXXFLAGS -r /src/liblouis/tests/synthesized_driver/*.c* -I/src/liblouis -I/src/liblouis/liblouis -o table_fuzzer.o
$CXX $CXXFLAGS table_fuzzer.o -o $OUT/table_fuzzer fuzz_lib.a

cp $OUT/table_fuzzer $OUT/fuzz_driver_$SANITIZER

# add more seeds than just one input to the corpus
rm -f "$OUT/table_fuzzer_seed_corpus.zip"
zip -r "$OUT/table_fuzzer_seed_corpus.zip" "$SRC/liblouis/tests/tables"
