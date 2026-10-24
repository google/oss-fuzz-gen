#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

int bstr_util_mem_index_of_c_nocase(const void *haystack, size_t haystack_len, const char *needle);

int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
  // Ensure size is sufficient for both haystack and needle
  if (size < 2) {
    return 0;
  }

  // Split the input data into haystack and needle
  size_t haystack_len = size / 2;
  const void *haystack = (const void *)data;
  const char *needle = (const char *)(data + haystack_len);

  // Ensure needle is null-terminated
  char needle_buffer[256];
  size_t needle_len = size - haystack_len;
  if (needle_len >= sizeof(needle_buffer)) {
    needle_len = sizeof(needle_buffer) - 1;
  }
  memcpy(needle_buffer, needle, needle_len);
  needle_buffer[needle_len] = '\0';

  // Call the function under test
  int result = bstr_util_mem_index_of_c_nocase(haystack, haystack_len, needle_buffer);

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

    LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
