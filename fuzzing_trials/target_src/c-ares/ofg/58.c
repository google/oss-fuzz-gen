#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "ares.h" // Ensure this header is available and correctly included for ares_dns_class_t

int LLVMFuzzerTestOneInput_58(const uint8_t *data, size_t size) {
  if (size < sizeof(ares_dns_class_t)) {
    return 0; // Not enough data to form a valid ares_dns_class_t
  }

  // Extract ares_dns_class_t from input data
  ares_dns_class_t qclass = *(const ares_dns_class_t *)data;

  // Call the function-under-test
  char *result = ares_dns_class_tostr(qclass);

  // Print the result to ensure it's being used
  if (result) {
    printf("DNS Class String: %s\n", result);
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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
