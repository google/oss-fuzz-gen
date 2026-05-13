// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_of_ptr at roaring64.c:390:21 in roaring64.h
// roaring64_bitmap_of_ptr at roaring64.c:390:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_andnot at roaring64.c:1653:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_copy at roaring64.c:259:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_andnot_cardinality at roaring64.c:1707:10 in roaring64.h
// roaring64_bitmap_remove_many at roaring64.c:809:6 in roaring64.h
// roaring64_bitmap_statistics at roaring64.c:1060:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "roaring64.h"

static void create_dummy_file(const uint8_t *data, size_t size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(data, 1, size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_86(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    // Create two bitmaps using roaring64_bitmap_of_ptr
    size_t n_args1 = Size / sizeof(uint64_t) / 2;
    size_t n_args2 = n_args1;

    const uint64_t *vals1 = (const uint64_t *)Data;
    const uint64_t *vals2 = (const uint64_t *)(Data + n_args1 * sizeof(uint64_t));

    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_of_ptr(n_args1, vals1);
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_of_ptr(n_args2, vals2);

    if (!bitmap1 || !bitmap2) {
        roaring64_bitmap_free(bitmap1);
        roaring64_bitmap_free(bitmap2);
        return 0;
    }

    // Test roaring64_bitmap_andnot
    roaring64_bitmap_t *andnot_result = roaring64_bitmap_andnot(bitmap1, bitmap2);
    if (andnot_result) {
        roaring64_bitmap_free(andnot_result);
    }

    // Test roaring64_bitmap_copy
    roaring64_bitmap_t *copy_result = roaring64_bitmap_copy(bitmap1);
    if (copy_result) {
        roaring64_bitmap_free(copy_result);
    }

    // Test roaring64_bitmap_andnot_cardinality
    uint64_t andnot_cardinality = roaring64_bitmap_andnot_cardinality(bitmap1, bitmap2);

    // Test roaring64_bitmap_remove_many
    roaring64_bitmap_remove_many(bitmap1, n_args1, vals1);

    // Test roaring64_bitmap_statistics
    roaring64_statistics_t stats;
    roaring64_bitmap_statistics(bitmap1, &stats);

    // Clean up
    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);

    // Create a dummy file
    create_dummy_file(Data, Size);

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

        LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    