// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring64_bitmap_of_ptr at roaring64.c:390:21 in roaring64.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring64_bitmap_move_from_roaring32 at roaring64.c:341:21 in roaring64.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring64_bitmap_or_cardinality at roaring64.c:1439:10 in roaring64.h
// roaring64_bitmap_copy at roaring64.c:259:21 in roaring64.h
// roaring64_bitmap_xor at roaring64.c:1507:21 in roaring64.h
// roaring64_bitmap_or at roaring64.c:1385:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <roaring/roaring.h>

static void initialize_roaring_bitmap(roaring_bitmap_t *bitmap, const uint8_t *data, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        roaring_bitmap_add(bitmap, data[i]);
    }
}

static roaring64_bitmap_t *create_roaring64_bitmap(const uint8_t *data, size_t size) {
    size_t num_elements = size / sizeof(uint64_t);
    const uint64_t *vals = (const uint64_t *)data;
    return roaring64_bitmap_of_ptr(num_elements, vals);
}

static void test_roaring64_bitmap_functions(const uint8_t *data, size_t size) {
    // Initialize a 32-bit roaring bitmap
    roaring_bitmap_t *r32 = roaring_bitmap_create();
    initialize_roaring_bitmap(r32, data, size);

    // Test roaring64_bitmap_move_from_roaring32
    roaring64_bitmap_t *r64 = roaring64_bitmap_move_from_roaring32(r32);
    roaring_bitmap_free(r32);

    // Create another roaring64 bitmap for further tests
    roaring64_bitmap_t *r64_other = create_roaring64_bitmap(data, size);

    if (r64 && r64_other) {
        // Test roaring64_bitmap_or_cardinality
        uint64_t or_cardinality = roaring64_bitmap_or_cardinality(r64, r64_other);

        // Test roaring64_bitmap_copy
        roaring64_bitmap_t *r64_copy = roaring64_bitmap_copy(r64);

        // Test roaring64_bitmap_xor
        roaring64_bitmap_t *r64_xor = roaring64_bitmap_xor(r64, r64_other);

        // Test roaring64_bitmap_or
        roaring64_bitmap_t *r64_or = roaring64_bitmap_or(r64, r64_other);

        // Cleanup
        roaring64_bitmap_free(r64_copy);
        roaring64_bitmap_free(r64_xor);
        roaring64_bitmap_free(r64_or);
    }

    roaring64_bitmap_free(r64);
    roaring64_bitmap_free(r64_other);
}

int LLVMFuzzerTestOneInput_27(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) {
        return 0;
    }

    test_roaring64_bitmap_functions(Data, Size);

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

        LLVMFuzzerTestOneInput_27(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    