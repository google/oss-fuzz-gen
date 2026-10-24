// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_size_in_bytes at roaring.c:1529:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_serialize at roaring.c:1513:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_deserialize at roaring.c:1576:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_frozen_view at roaring.c:3141:25 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_frozen_size_in_bytes at roaring.c:3018:8 in roaring.h
// roaring_bitmap_frozen_serialize at roaring.c:3053:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring64_bitmap_portable_deserialize_safe at roaring64.c:2282:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring_bitmap_portable_size_in_bytes at roaring.c:1537:8 in roaring.h
// roaring_bitmap_portable_serialize at roaring.c:1572:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "roaring.h"
#include "roaring64.h"

static roaring_bitmap_t* create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return NULL;

    for (size_t i = 0; i < Size; i++) {
        roaring_bitmap_add(bitmap, Data[i]);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_69(const uint8_t *Data, size_t Size) {
    if (Size < 5) return 0;

    // Test roaring_bitmap_serialize and roaring_bitmap_deserialize
    roaring_bitmap_t *bitmap = create_random_bitmap(Data, Size);
    if (!bitmap) return 0;

    size_t serialized_size = roaring_bitmap_size_in_bytes(bitmap);
    char *buffer = (char *)malloc(serialized_size);
    if (!buffer) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    size_t written_bytes = roaring_bitmap_serialize(bitmap, buffer);
    if (written_bytes != serialized_size) {
        free(buffer);
        roaring_bitmap_free(bitmap);
        return 0;
    }

    roaring_bitmap_t *deserialized_bitmap = roaring_bitmap_deserialize(buffer);
    if (deserialized_bitmap) {
        roaring_bitmap_free(deserialized_bitmap);
    }

    free(buffer);
    roaring_bitmap_free(bitmap);

    // Test roaring_bitmap_frozen_view
    if (Size >= 32) {
        const roaring_bitmap_t *frozen_view = roaring_bitmap_frozen_view((const char *)Data, Size);
        if (frozen_view) {
            roaring_bitmap_free((roaring_bitmap_t *)frozen_view);
        }
    }

    // Test roaring_bitmap_frozen_serialize
    bitmap = create_random_bitmap(Data, Size);
    if (bitmap) {
        size_t frozen_size = roaring_bitmap_frozen_size_in_bytes(bitmap);
        buffer = (char *)malloc(frozen_size);
        if (buffer) {
            roaring_bitmap_frozen_serialize(bitmap, buffer);
            free(buffer);
        }
        roaring_bitmap_free(bitmap);
    }

    // Test roaring64_bitmap_portable_deserialize_safe
    roaring64_bitmap_t *bitmap64 = roaring64_bitmap_portable_deserialize_safe((const char *)Data, Size);
    if (bitmap64) {
        roaring64_bitmap_free(bitmap64);
    }

    // Test roaring_bitmap_portable_serialize
    bitmap = create_random_bitmap(Data, Size);
    if (bitmap) {
        size_t portable_size = roaring_bitmap_portable_size_in_bytes(bitmap);
        buffer = (char *)malloc(portable_size);
        if (buffer) {
            size_t portable_written_bytes = roaring_bitmap_portable_serialize(bitmap, buffer);
            if (portable_written_bytes == portable_size) {
                // Successfully serialized
            }
            free(buffer);
        }
        roaring_bitmap_free(bitmap);
    }

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

        LLVMFuzzerTestOneInput_69(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    