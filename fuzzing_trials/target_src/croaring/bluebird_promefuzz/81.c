#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include "roaring/roaring.h"

static roaring_bitmap_t *create_random_bitmap(const uint8_t *Data, size_t Size) {
    if (Size < 4) return NULL;
    size_t num_elements = Data[0] % 100; // limit the number of elements for fuzzing
    if (Size < 1 + num_elements * sizeof(uint32_t)) return NULL; // Ensure there's enough data

    uint32_t *elements = (uint32_t *)malloc(num_elements * sizeof(uint32_t));
    if (!elements) return NULL;

    for (size_t i = 0; i < num_elements; i++) {
        elements[i] = *((uint32_t *)(Data + 1 + i * sizeof(uint32_t)));
    }

    roaring_bitmap_t *bitmap = roaring_bitmap_of_ptr(num_elements, elements);
    free(elements);
    return bitmap;
}

int LLVMFuzzerTestOneInput_81(const uint8_t *Data, size_t Size) {
    if (Size < 5) return 0;

    // Fuzzing roaring_bitmap_of_ptr
    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data + Size / 2, Size / 2);
    
    if (!bitmap1 || !bitmap2) {
        roaring_bitmap_free(bitmap1);
        roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Fuzzing roaring_bitmap_and
    roaring_bitmap_t *and_bitmap = roaring_bitmap_and(bitmap1, bitmap2);
    if (and_bitmap) {
        roaring_bitmap_printf_describe(and_bitmap);
        roaring_bitmap_free(and_bitmap);
    }

    // Fuzzing roaring_bitmap_deserialize
    roaring_bitmap_t *deserialized_bitmap = roaring_bitmap_deserialize(Data);
    if (deserialized_bitmap) {
        roaring_bitmap_printf_describe(deserialized_bitmap);
        roaring_bitmap_free(deserialized_bitmap);
    }

    // Fuzzing roaring_bitmap_portable_size_in_bytes
    size_t size_in_bytes1 = roaring_bitmap_portable_size_in_bytes(bitmap1);
    size_t size_in_bytes2 = roaring_bitmap_portable_size_in_bytes(bitmap2);

    printf("Size in bytes bitmap1: %zu\n", size_in_bytes1);
    printf("Size in bytes bitmap2: %zu\n", size_in_bytes2);

    roaring_bitmap_free(bitmap1);
    roaring_bitmap_free(bitmap2);

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

    LLVMFuzzerTestOneInput_81(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
