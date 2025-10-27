#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netcdf.h>
#include <netcdf_mem.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  int ncid;
  if (nc_open_mem("/tmp/fuzz.nc", 0, Size, (void *)Data, &ncid) == NC_NOERR) {
    nc_close(ncid);
  }
  return 0;
}
