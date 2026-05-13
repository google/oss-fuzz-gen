#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include "roaring/roaring.h"

static roaring_bitmap_t* create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < Size; i++) {
        roaring_bitmap_add(bitmap, Data[i]);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size / 2);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data + Size / 2, Size / 2);
    if (!bitmap1 || !bitmap2) {
        roaring_bitmap_free(bitmap1);
        roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Test roaring_bitmap_lazy_xor
    roaring_bitmap_t *xor_bitmap = roaring_bitmap_lazy_xor(bitmap1, bitmap2);
    if (xor_bitmap) {
        roaring_bitmap_repair_after_lazy(xor_bitmap);
        roaring_bitmap_free(xor_bitmap);
    }

    // Test roaring_bitmap_add_offset
    int64_t offset = (int64_t)(Data[0] % 256) - 128;
    roaring_bitmap_t *offset_bitmap = roaring_bitmap_add_offset(bitmap1, offset);
    if (offset_bitmap) {
        roaring_bitmap_free(offset_bitmap);
    }

    // Test roaring_bitmap_and_inplace
    roaring_bitmap_and_inplace(bitmap1, bitmap2);

    // Test roaring_bitmap_statistics
    roaring_statistics_t stats;
    roaring_bitmap_statistics(bitmap1, &stats);

    // Test roaring_bitmap_lazy_or
    bool bitsetconversion = Data[0] % 2 == 0;
    roaring_bitmap_t *or_bitmap = roaring_bitmap_lazy_or(bitmap1, bitmap2, bitsetconversion);
    if (or_bitmap) {
        roaring_bitmap_repair_after_lazy(or_bitmap);
        roaring_bitmap_free(or_bitmap);
    }

    // Cleanup
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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
