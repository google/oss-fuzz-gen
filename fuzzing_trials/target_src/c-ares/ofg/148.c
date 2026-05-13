#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h> // Include the correct header for ares_dns_rr_key_t and ares_dns_rr_key_tostr

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
  if (size < sizeof(ares_dns_rr_key_t)) {
    return 0; /* Not enough data to form a valid ares_dns_rr_key_t */
  }

  // Create a copy of the input data to use as ares_dns_rr_key_t
  ares_dns_rr_key_t key;
  memcpy(&key, data, sizeof(ares_dns_rr_key_t));

  // Call the function-under-test
  char *result = ares_dns_rr_key_tostr(key);

  // Free the result if it's not NULL
  if (result) {
    free(result);
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

    LLVMFuzzerTestOneInput_148(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
