#!/bin/bash
for file in "src/arg_getopt_long.c src/argtable3.c src/arg_dbl.c src/arg_int.c src/arg_dstr.c src/arg_utils.c src/arg_str.c src/arg_end.c src/arg_rex.c src/arg_rem.c src/arg_cmd.c src/arg_hashtable.c src/arg_file.c src/arg_date.c src/arg_lit.c"; do
  $CC $CFLAGS -c ${file}
done

rm -f ./test*.o
llvm-ar rcs libfuzz.a *.o


for fuzzer in $SRC/fuzzers/*; do
  fuzzer_target=$(basename $fuzzer)
  fuzzer_target="${fuzzer_target%.*}"
  $CC $CFLAGS $LIB_FUZZING_ENGINE ${fuzzer} -Wl,--whole-archive $SRC/argtable3/libfuzz.a -Wl,--allow-multiple-definition -I$SRC/argtable3/src -I$SRC/argtable3/tests -o $OUT/${fuzzer_target}
done