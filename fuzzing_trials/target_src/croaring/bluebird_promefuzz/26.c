#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "roaring/roaring.h"

static void fuzz_roaring_bitmap_and(const uint8_t *Data, size_t Size) {
    if (Size < 8) return; // Need at least two uint32_t values

    size_t half_size = Size / 2;
    const uint32_t *vals1 = (const uint32_t *)Data;
    const uint32_t *vals2 = (const uint32_t *)(Data + half_size);

    roaring_bitmap_t *bitmap1 = roaring_bitmap_of_ptr(half_size / sizeof(uint32_t), vals1);
    roaring_bitmap_t *bitmap2 = roaring_bitmap_of_ptr((Size - half_size) / sizeof(uint32_t), vals2);

    if (bitmap1 && bitmap2) {
        roaring_bitmap_t *and_bitmap = roaring_bitmap_and(bitmap1, bitmap2);
        if (and_bitmap) {
            roaring_bitmap_printf(and_bitmap);
            roaring_bitmap_free(and_bitmap);
        }
    }

    if (bitmap1) roaring_bitmap_free(bitmap1);
    if (bitmap2) roaring_bitmap_free(bitmap2);
}

static void fuzz_roaring_bitmap_of(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;

    size_t n = Size / sizeof(uint32_t);
    const uint32_t *vals = (const uint32_t *)Data;

    roaring_bitmap_t *bitmap = roaring_bitmap_of_ptr(n, vals);
    if (bitmap) {
        roaring_bitmap_printf(bitmap);
        roaring_bitmap_free(bitmap);
    }
}

static void fuzz_roaring_bitmap_equals(const uint8_t *Data, size_t Size) {
    if (Size < 8) return; // Need at least two uint32_t values

    size_t half_size = Size / 2;
    const uint32_t *vals1 = (const uint32_t *)Data;
    const uint32_t *vals2 = (const uint32_t *)(Data + half_size);

    roaring_bitmap_t *bitmap1 = roaring_bitmap_of_ptr(half_size / sizeof(uint32_t), vals1);
    roaring_bitmap_t *bitmap2 = roaring_bitmap_of_ptr((Size - half_size) / sizeof(uint32_t), vals2);

    if (bitmap1 && bitmap2) {
        bool equals = roaring_bitmap_equals(bitmap1, bitmap2);
        printf("Bitmaps are equal: %s\n", equals ? "true" : "false");
    }

    if (bitmap1) roaring_bitmap_free(bitmap1);
    if (bitmap2) roaring_bitmap_free(bitmap2);
}

static void fuzz_roaring_bitmap_printf_describe(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return;

    size_t n = Size / sizeof(uint32_t);
    const uint32_t *vals = (const uint32_t *)Data;

    roaring_bitmap_t *bitmap = roaring_bitmap_of_ptr(n, vals);
    if (bitmap) {
        roaring_bitmap_printf_describe(bitmap);
        roaring_bitmap_free(bitmap);
    }
}

int LLVMFuzzerTestOneInput_26(const uint8_t *Data, size_t Size) {
    fuzz_roaring_bitmap_and(Data, Size);
    fuzz_roaring_bitmap_of(Data, Size);
    fuzz_roaring_bitmap_equals(Data, Size);
    fuzz_roaring_bitmap_printf_describe(Data, Size);

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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
