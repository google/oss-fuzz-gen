// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_minimum at roaring64.c:961:10 in roaring64.h
// roaring64_bitmap_get_cardinality at roaring64.c:892:10 in roaring64.h
// roaring64_bitmap_to_uint64_array at roaring64.c:2736:6 in roaring64.h
// roaring64_bitmap_rank at roaring64.c:663:10 in roaring64.h
// roaring64_bitmap_get_cardinality at roaring64.c:892:10 in roaring64.h
// roaring64_bitmap_range_cardinality at roaring64.c:904:10 in roaring64.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_maximum at roaring64.c:971:10 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <roaring64.h>

static void test_roaring64_bitmap_maximum(const roaring64_bitmap_t *bitmap) {
    uint64_t max = roaring64_bitmap_maximum(bitmap);
    (void)max; // Suppress unused variable warning
}

static void test_roaring64_bitmap_minimum(const roaring64_bitmap_t *bitmap) {
    uint64_t min = roaring64_bitmap_minimum(bitmap);
    (void)min; // Suppress unused variable warning
}

static void test_roaring64_bitmap_to_uint64_array(const roaring64_bitmap_t *bitmap) {
    uint64_t cardinality = roaring64_bitmap_get_cardinality(bitmap);
    uint64_t *array = malloc(cardinality * sizeof(uint64_t));
    if (array) {
        roaring64_bitmap_to_uint64_array(bitmap, array);
        free(array);
    }
}

static void test_roaring64_bitmap_rank(const roaring64_bitmap_t *bitmap, uint64_t val) {
    uint64_t rank = roaring64_bitmap_rank(bitmap, val);
    (void)rank; // Suppress unused variable warning
}

static void test_roaring64_bitmap_get_cardinality(const roaring64_bitmap_t *bitmap) {
    uint64_t cardinality = roaring64_bitmap_get_cardinality(bitmap);
    (void)cardinality; // Suppress unused variable warning
}

static void test_roaring64_bitmap_range_cardinality(const roaring64_bitmap_t *bitmap, uint64_t min, uint64_t max) {
    uint64_t range_cardinality = roaring64_bitmap_range_cardinality(bitmap, min, max);
    (void)range_cardinality; // Suppress unused variable warning
}

int LLVMFuzzerTestOneInput_29(const uint8_t *Data, size_t Size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return 0; // Failed to create bitmap
    }

    // Populate the bitmap with data from the fuzzer
    for (size_t i = 0; i < Size / sizeof(uint64_t); i++) {
        uint64_t value;
        memcpy(&value, Data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }

    // Test the target functions with the bitmap
    test_roaring64_bitmap_maximum(bitmap);
    test_roaring64_bitmap_minimum(bitmap);
    test_roaring64_bitmap_to_uint64_array(bitmap);
    test_roaring64_bitmap_rank(bitmap, 0); // Example rank query with value 0
    test_roaring64_bitmap_get_cardinality(bitmap);
    test_roaring64_bitmap_range_cardinality(bitmap, 0, UINT64_MAX); // Example range query

    // Clean up
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

        LLVMFuzzerTestOneInput_29(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    