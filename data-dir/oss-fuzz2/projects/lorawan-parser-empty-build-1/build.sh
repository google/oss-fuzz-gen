#!/bin/bash
autoreconf -fi
./configure
make

for fuzzer in $SRC/fuzzers/*; do
  fuzzer_target=$(basename $fuzzer)
  fuzzer_target="${fuzzer_target%.*}"
  $CC $CFLAGS $LIB_FUZZING_ENGINE ${fuzzer} -Wl,--whole-archive $SRC/lorawan-parser/lw/.libs/liblorawan.a -Wl,--whole-archive $SRC/lorawan-parser/lib/libloragw$SRC/.libs/libloragw.a -Wl,--whole-archive $SRC/lorawan-parser/lib/.libs/lib.a -Wl,--allow-multiple-definition -I$SRC/lorawan-parser/util/parser -I$SRC/lorawan-parser/lw -I$SRC/lorawan-parser/lib/libloragw/inc -I$SRC/lorawan-parser/lib -o $OUT/${fuzzer_target}
done