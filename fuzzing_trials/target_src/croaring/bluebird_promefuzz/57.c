#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "roaring/roaring.h"

static roaring_bitmap_t *create_random_bitmap(const uint8_t *data, size_t size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < size; i++) {
        roaring_bitmap_add(bitmap, data[i]);
    }

    return bitmap;
}

static void fuzz_roaring_bitmap_lazy_xor_inplace(roaring_bitmap_t *r1, const roaring_bitmap_t *r2) {
    roaring_bitmap_lazy_xor_inplace(r1, r2);
}

static void fuzz_roaring_bitmap_set_copy_on_write(roaring_bitmap_t *r, bool cow) {
    roaring_bitmap_set_copy_on_write(r, cow);
}

static roaring_bitmap_t *fuzz_roaring_bitmap_lazy_or(const roaring_bitmap_t *r1, const roaring_bitmap_t *r2, bool bitsetconversion) {
    return roaring_bitmap_lazy_or(r1, r2, bitsetconversion);
}

static bool fuzz_roaring_bitmap_remove_checked(roaring_bitmap_t *r, uint32_t x) {
    return roaring_bitmap_remove_checked(r, x);
}

static bool fuzz_roaring_bitmap_overwrite(roaring_bitmap_t *dest, const roaring_bitmap_t *src) {
    return roaring_bitmap_overwrite(dest, src);
}

static bool fuzz_roaring_unshare_all(roaring_bitmap_t *r) {
    return roaring_unshare_all(r);
}

int LLVMFuzzerTestOneInput_57(const uint8_t *Data, size_t Size) {
    if (Size < 2) return 0;

    // Create bitmaps from input data
    roaring_bitmap_t *bitmap1 = create_random_bitmap(Data, Size / 2);
    roaring_bitmap_t *bitmap2 = create_random_bitmap(Data + Size / 2, Size / 2);

    if (!bitmap1 || !bitmap2) {
        roaring_bitmap_free(bitmap1);
        roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Fuzz roaring_bitmap_lazy_xor_inplace
    fuzz_roaring_bitmap_lazy_xor_inplace(bitmap1, bitmap2);

    // Fuzz roaring_bitmap_set_copy_on_write
    fuzz_roaring_bitmap_set_copy_on_write(bitmap1, Data[0] % 2 == 0);

    // Fuzz roaring_bitmap_lazy_or
    roaring_bitmap_t *lazy_or_result = fuzz_roaring_bitmap_lazy_or(bitmap1, bitmap2, Data[1] % 2 == 0);
    if (lazy_or_result) {
        roaring_bitmap_free(lazy_or_result);
    }

    // Fuzz roaring_bitmap_remove_checked
    fuzz_roaring_bitmap_remove_checked(bitmap1, Data[0]);

    // Fuzz roaring_bitmap_overwrite
    fuzz_roaring_bitmap_overwrite(bitmap1, bitmap2);

    // Fuzz roaring_unshare_all
    fuzz_roaring_unshare_all(bitmap1);

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

    LLVMFuzzerTestOneInput_57(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
