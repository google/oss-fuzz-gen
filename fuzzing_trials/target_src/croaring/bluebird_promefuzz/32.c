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
#include "roaring/roaring64.h"

static void initialize_bitmap(roaring64_bitmap_t *bitmap) {
    // Initialize the bitmap with some default values
    // In a real fuzzing scenario, you would initialize with random data
    roaring64_bitmap_add(bitmap, rand() % 100);
    roaring64_bitmap_add(bitmap, rand() % 100 + 100);
}

int LLVMFuzzerTestOneInput_32(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    roaring64_bitmap_t *r1 = roaring64_bitmap_create();
    roaring64_bitmap_t *r2 = roaring64_bitmap_create();
    roaring64_bitmap_t *r3 = roaring64_bitmap_create();

    if (!r1 || !r2 || !r3) {
        roaring64_bitmap_free(r1);
        roaring64_bitmap_free(r2);
        roaring64_bitmap_free(r3);
        return 0;
    }

    // Initialize bitmaps
    initialize_bitmap(r1);
    initialize_bitmap(r2);
    initialize_bitmap(r3);

    // Fuzzing roaring64_bitmap_or_inplace
    roaring64_bitmap_or_inplace(r1, r2);

    // Fuzzing roaring64_bitmap_andnot_inplace
    roaring64_bitmap_andnot_inplace(r1, r2);

    // Fuzzing roaring64_bitmap_overwrite
    roaring64_bitmap_overwrite(r1, r3);

    // Fuzzing roaring64_bitmap_and
    roaring64_bitmap_t *and_result = roaring64_bitmap_and(r1, r2);
    if (and_result) {
        roaring64_bitmap_free(and_result);
    }

    // Fuzzing roaring64_bitmap_is_strict_subset
    bool is_subset = roaring64_bitmap_is_strict_subset(r1, r2);

    // Fuzzing roaring64_bitmap_xor_inplace
    roaring64_bitmap_xor_inplace(r1, r2);

    // Clean up
    roaring64_bitmap_free(r1);
    roaring64_bitmap_free(r2);
    roaring64_bitmap_free(r3);

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
