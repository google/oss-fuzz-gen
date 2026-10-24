// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_portable_deserialize_safe at roaring.c:1541:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_portable_deserialize at roaring.c:1563:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_portable_deserialize_frozen at roaring.c:3270:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_or at roaring.c:877:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_size_in_bytes at roaring.c:1529:8 in roaring.h
// roaring_bitmap_serialize at roaring.c:1513:8 in roaring.h
// roaring_bitmap_frozen_serialize at roaring.c:3053:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "roaring.h"

static roaring_bitmap_t *create_random_bitmap() {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;
    for (uint32_t i = 0; i < 1000; ++i) {
        roaring_bitmap_add(bitmap, rand() % 100000);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_103(const uint8_t *Data, size_t Size) {
    if (Size < 8) return 0;

    // Test roaring_bitmap_portable_deserialize_safe
    roaring_bitmap_t *bitmap1 = roaring_bitmap_portable_deserialize_safe((const char *)Data, Size);
    if (bitmap1) {
        roaring_bitmap_free(bitmap1);
    }

    // Test roaring_bitmap_portable_deserialize
    roaring_bitmap_t *bitmap2 = roaring_bitmap_portable_deserialize((const char *)Data);
    if (bitmap2) {
        roaring_bitmap_free(bitmap2);
    }

    // Test roaring_bitmap_portable_deserialize_frozen
    roaring_bitmap_t *bitmap3 = roaring_bitmap_portable_deserialize_frozen((const char *)Data);
    if (bitmap3) {
        roaring_bitmap_free(bitmap3);
    }

    // Create random bitmaps for other tests
    roaring_bitmap_t *rand_bitmap1 = create_random_bitmap();
    roaring_bitmap_t *rand_bitmap2 = create_random_bitmap();

    if (rand_bitmap1 && rand_bitmap2) {
        // Test roaring_bitmap_or
        roaring_bitmap_t *bitmap_or = roaring_bitmap_or(rand_bitmap1, rand_bitmap2);
        if (bitmap_or) {
            roaring_bitmap_free(bitmap_or);
        }

        // Prepare buffer for serialization tests
        size_t serialize_size = roaring_bitmap_size_in_bytes(rand_bitmap1);
        char *buffer = (char *)malloc(serialize_size);
        if (buffer) {
            // Test roaring_bitmap_serialize
            size_t bytes_written = roaring_bitmap_serialize(rand_bitmap1, buffer);
            (void)bytes_written; // suppress unused variable warning

            // Test roaring_bitmap_frozen_serialize
            roaring_bitmap_frozen_serialize(rand_bitmap1, buffer);

            free(buffer);
        }
    }

    roaring_bitmap_free(rand_bitmap1);
    roaring_bitmap_free(rand_bitmap2);

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

        LLVMFuzzerTestOneInput_103(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    