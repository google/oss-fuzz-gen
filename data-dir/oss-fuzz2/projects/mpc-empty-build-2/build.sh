#!/bin/bash
sed -i 's/-Werror/-Wno-error/g' ./Makefile
sed -i 's/CC=/#CC=/g' ./Makefile
sed -i 's/CXX=/#CXX=/g' ./Makefile
sed -i 's/CC =/#CC=/g' ./Makefile
sed -i 's/CXX =/#CXX=/g' ./Makefile
make V=1 || true

for fuzzer in $SRC/fuzzers/*; do
  fuzzer_target=$(basename $fuzzer)
  fuzzer_target="${fuzzer_target%.*}"
  $CC $CFLAGS $LIB_FUZZING_ENGINE ${fuzzer} -Wl,--whole-archive $SRC/mpc/build/libmpc.a -Wl,--allow-multiple-definition -I$SRC/mpc -I$SRC/mpc/tests -o $OUT/${fuzzer_target}
done