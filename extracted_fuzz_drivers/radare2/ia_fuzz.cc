#include <r_core.h>
#include <stdio.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  RCore *r;
  char path[128];

  r = r_core_new();

  r_core_cmdf(r, "o malloc://%d", Size);
  r_io_write_at(r->io, 0, Data, Size);

  r_core_cmd0(r, "oba 0");
  r_core_cmd0(r, "ia");

  r_core_free(r);
  return 0;
}
