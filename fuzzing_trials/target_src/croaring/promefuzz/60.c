// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_internal_validate at roaring64.c:1110:6 in roaring64.h
// roaring64_bitmap_equals at roaring64.c:1116:6 in roaring64.h
// roaring64_bitmap_and at roaring64.c:1176:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_is_subset at roaring64.c:1137:6 in roaring64.h
// roaring64_bitmap_is_strict_subset at roaring64.c:1169:6 in roaring64.h
// roaring64_bitmap_intersect at roaring64.c:1331:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
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
#include "roaring64.h"

static roaring64_bitmap_t* create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (bitmap == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < Size / sizeof(uint64_t); i++) {
        uint64_t value;
        memcpy(&value, Data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_60(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    roaring64_bitmap_t *bitmap1 = create_random_bitmap(Data, Size);
    roaring64_bitmap_t *bitmap2 = create_random_bitmap(Data, Size);

    if (bitmap1 == NULL || bitmap2 == NULL) {
        roaring64_bitmap_free(bitmap1);
        roaring64_bitmap_free(bitmap2);
        return 0;
    }

    const char *reason = NULL;
    bool is_valid = roaring64_bitmap_internal_validate(bitmap1, &reason);
    if (!is_valid && reason != NULL) {
        printf("Validation failed: %s\n", reason);
    }

    bool are_equal = roaring64_bitmap_equals(bitmap1, bitmap2);
    roaring64_bitmap_t *intersection = roaring64_bitmap_and(bitmap1, bitmap2);
    if (intersection != NULL) {
        roaring64_bitmap_free(intersection);
    }

    bool is_subset = roaring64_bitmap_is_subset(bitmap1, bitmap2);
    bool is_strict_subset = roaring64_bitmap_is_strict_subset(bitmap1, bitmap2);
    bool do_intersect = roaring64_bitmap_intersect(bitmap1, bitmap2);

    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);

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

        LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    