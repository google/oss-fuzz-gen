#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "/src/croaring/include/roaring/roaring.h"

// Define a simple iterator function
bool simple_iterator(uint64_t value, void *param) {
  // For the purpose of fuzzing, we can simply print the value
  // or perform any other operation. Here, we just return true.
  return true;
}

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
  if (size < sizeof(uint64_t)) {
    return 0; // Not enough data to create a bitmap
  }

  // Initialize a roaring64 bitmap
  roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
  if (!bitmap) {
    return 0; // Failed to create bitmap
  }

  // Add some elements to the bitmap using the input data
  for (size_t i = 0; i < size / sizeof(uint64_t); i++) {
    uint64_t value = ((uint64_t *)data)[i];
    roaring64_bitmap_add(bitmap, value);
  }

  // Call the function-under-test
  roaring64_bitmap_iterate(bitmap, simple_iterator, NULL);

  // Free the bitmap
  roaring64_bitmap_free(bitmap);

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

    LLVMFuzzerTestOneInput_94(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
