// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add_offset_signed at roaring64.c:1959:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_add_checked at roaring64.c:430:6 in roaring64.h
// roaring64_bitmap_add_checked at roaring64.c:430:6 in roaring64.h
// roaring64_bitmap_equals at roaring64.c:1116:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_add_checked at roaring64.c:430:6 in roaring64.h
// roaring64_bitmap_add_checked at roaring64.c:430:6 in roaring64.h
// roaring64_bitmap_or at roaring64.c:1385:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include "roaring64.h"

static void fuzz_roaring64_bitmap_add_offset_signed(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t) + 1) return;

    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return;

    uint64_t offset = *(const uint64_t *)Data;
    Data += sizeof(uint64_t);
    bool positive = *Data & 1;

    roaring64_bitmap_t *result = roaring64_bitmap_add_offset_signed(bitmap, positive, offset);
    if (result) {
        roaring64_bitmap_free(result);
    }

    roaring64_bitmap_free(bitmap);
}

static void fuzz_roaring64_bitmap_equals(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(uint64_t)) return;

    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();
    if (!bitmap1 || !bitmap2) {
        roaring64_bitmap_free(bitmap1);
        roaring64_bitmap_free(bitmap2);
        return;
    }

    uint64_t val1 = *(const uint64_t *)Data;
    Data += sizeof(uint64_t);
    uint64_t val2 = *(const uint64_t *)Data;
    roaring64_bitmap_add_checked(bitmap1, val1);
    roaring64_bitmap_add_checked(bitmap2, val2);

    bool equals = roaring64_bitmap_equals(bitmap1, bitmap2);

    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);
}

static void fuzz_roaring64_bitmap_or(const uint8_t *Data, size_t Size) {
    if (Size < 2 * sizeof(uint64_t)) return;

    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();
    if (!bitmap1 || !bitmap2) {
        roaring64_bitmap_free(bitmap1);
        roaring64_bitmap_free(bitmap2);
        return;
    }

    uint64_t val1 = *(const uint64_t *)Data;
    Data += sizeof(uint64_t);
    uint64_t val2 = *(const uint64_t *)Data;
    roaring64_bitmap_add_checked(bitmap1, val1);
    roaring64_bitmap_add_checked(bitmap2, val2);

    roaring64_bitmap_t *result = roaring64_bitmap_or(bitmap1, bitmap2);
    if (result) {
        roaring64_bitmap_free(result);
    }

    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);
}

int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    fuzz_roaring64_bitmap_add_offset_signed(Data, Size);
    fuzz_roaring64_bitmap_equals(Data, Size);
    fuzz_roaring64_bitmap_or(Data, Size);
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

        LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    