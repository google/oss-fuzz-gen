#include "../../liblouis/liblouis.h"
#include <filesystem>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char new_file[256];
  sprintf(new_file, "/tmp/libfuzzer.uti");

  FILE *fp = fopen(new_file, "wb");
  if (!fp)
    return 0;
  fwrite(data, size, 1, fp);
  fclose(fp);

  char *table = "empty.ctb";
  lou_compileString(table, "include /tmp/libfuzzer.uti");

  lou_free();
  std::__fs::filesystem::remove_all("/tmp/libfuzzer.uti");

  return 0;
}
