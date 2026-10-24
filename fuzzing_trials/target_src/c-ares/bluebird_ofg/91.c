#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "ares.h"

// Fuzzing entry point
int LLVMFuzzerTestOneInput_91(const uint8_t *data, size_t size) {
  // Allocate memory for the string, ensuring it's null-terminated
  char *str = (char *)malloc(size + 1);
  if (str == NULL) {
    return 0; // Exit if memory allocation fails
  }
  memcpy(str, data, size);
  str[size] = '\0'; // Null-terminate the string

  // Declare a variable for the DNS class
  ares_dns_class_t qclass;

  // Call the function under test
  ares_dns_class_fromstr(&qclass, str);

  // Free the allocated memory
  free(str);

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

    LLVMFuzzerTestOneInput_91(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
