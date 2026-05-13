#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h> // Include for memcpy and strlen
#include "ares.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
  if (size < sizeof(ares_dns_rec_type_t)) {
    return 0;
  }

  ares_dns_rec_type_t type;
  /* Copy data into the type variable, ensuring it's properly aligned */
  memcpy(&type, data, sizeof(ares_dns_rec_type_t));

  /* Call the function-under-test */
  char *result = ares_dns_rec_type_tostr(type);

  /* If the function returns a non-null string, we can perform some checks */
  if (result != NULL) {
    /* For fuzzing purposes, we might want to ensure the string is null-terminated */
    size_t len = strlen(result);
    if (len > 0) {
      /* Optionally, we could do something with the result, like logging or further checks */
    }
  }

  return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
