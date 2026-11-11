#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "libyang.h"

int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
  struct timespec ts;
  char *str = NULL;
  LY_ERR result;

  // Ensure we have enough data to populate the timespec structure
  if (size < sizeof(struct timespec)) {
    return 0;
  }

  // Copy data into the timespec structure
  memcpy(&ts, data, sizeof(struct timespec));

  // Call the function-under-test
  result = ly_time_ts2str(&ts, &str);

  // Free the allocated string if it was successfully created
  if (result == LY_SUCCESS && str != NULL) {
    free(str);
  }

  return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
