// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_portable_size_in_bytes at roaring.c:1537:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_portable_serialize at roaring.c:1572:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_size_in_bytes at roaring.c:1529:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_serialize at roaring.c:1513:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_deserialize at roaring.c:1576:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_frozen_view at roaring.c:3141:25 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_bitmap_frozen_size_in_bytes at roaring.c:3018:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_frozen_serialize at roaring.c:3053:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring64_bitmap_portable_deserialize_safe at roaring64.c:2282:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "roaring.h"
#include "roaring64.h"

static void fuzz_roaring_bitmap_serialize(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(roaring_bitmap_t)) return;

    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return;

    // Simulate filling the bitmap with some data
    for (size_t i = 0; i < Size / sizeof(uint32_t); ++i) {
        uint32_t value;
        memcpy(&value, Data + i * sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_add(bitmap, value);
    }

    size_t buffer_size = roaring_bitmap_size_in_bytes(bitmap);
    char *buffer = (char *)malloc(buffer_size);
    if (!buffer) {
        roaring_bitmap_free(bitmap);
        return;
    }

    size_t serialized_bytes = roaring_bitmap_serialize(bitmap, buffer);
    if (serialized_bytes != buffer_size) {
        // Handle serialization error
    }

    roaring_bitmap_free(bitmap);
    free(buffer);
}

static void fuzz_roaring_bitmap_deserialize(const uint8_t *Data, size_t Size) {
    if (Size < 5) return; // Minimum size check

    // Ensure the buffer is large enough to contain the expected number of elements
    uint32_t card;
    memcpy(&card, Data + 1, sizeof(uint32_t));
    size_t required_size = 1 + sizeof(uint32_t) + card * sizeof(uint32_t);
    if (Size < required_size) return;

    roaring_bitmap_t *bitmap = roaring_bitmap_deserialize(Data);
    if (bitmap) {
        roaring_bitmap_free(bitmap);
    }
}

static void fuzz_roaring_bitmap_frozen_view(const uint8_t *Data, size_t Size) {
    if (Size < 32) return; // Minimum size for alignment

    // Ensure the buffer is 32-byte aligned
    char *aligned_buffer = (char *)(((uintptr_t)Data + 31) & ~((uintptr_t)31));
    size_t aligned_size = Size - (aligned_buffer - (char *)Data);

    const roaring_bitmap_t *bitmap = roaring_bitmap_frozen_view(aligned_buffer, aligned_size);
    if (bitmap) {
        roaring_bitmap_free((roaring_bitmap_t *)bitmap);
    }
}

static void fuzz_roaring_bitmap_frozen_serialize(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(roaring_bitmap_t)) return;

    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return;

    // Simulate filling the bitmap with some data
    for (size_t i = 0; i < Size / sizeof(uint32_t); ++i) {
        uint32_t value;
        memcpy(&value, Data + i * sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_add(bitmap, value);
    }

    size_t buffer_size = roaring_bitmap_frozen_size_in_bytes(bitmap);
    char *buffer = (char *)malloc(buffer_size);
    if (!buffer) {
        roaring_bitmap_free(bitmap);
        return;
    }

    roaring_bitmap_frozen_serialize(bitmap, buffer);

    roaring_bitmap_free(bitmap);
    free(buffer);
}

static void fuzz_roaring64_bitmap_portable_deserialize_safe(const uint8_t *Data, size_t Size) {
    if (Size < 5) return; // Minimum size check

    roaring64_bitmap_t *bitmap = roaring64_bitmap_portable_deserialize_safe((const char *)Data, Size);
    if (bitmap) {
        roaring64_bitmap_free(bitmap);
    }
}

static void fuzz_roaring_bitmap_portable_serialize(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(roaring_bitmap_t)) return;

    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return;

    // Simulate filling the bitmap with some data
    for (size_t i = 0; i < Size / sizeof(uint32_t); ++i) {
        uint32_t value;
        memcpy(&value, Data + i * sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_add(bitmap, value);
    }

    size_t buffer_size = roaring_bitmap_portable_size_in_bytes(bitmap);
    char *buffer = (char *)malloc(buffer_size);
    if (!buffer) {
        roaring_bitmap_free(bitmap);
        return;
    }

    size_t serialized_bytes = roaring_bitmap_portable_serialize(bitmap, buffer);
    if (serialized_bytes != buffer_size) {
        // Handle serialization error
    }

    roaring_bitmap_free(bitmap);
    free(buffer);
}

int LLVMFuzzerTestOneInput_80(const uint8_t *Data, size_t Size) {
    fuzz_roaring_bitmap_serialize(Data, Size);
    fuzz_roaring_bitmap_deserialize(Data, Size);
    fuzz_roaring_bitmap_frozen_view(Data, Size);
    fuzz_roaring_bitmap_frozen_serialize(Data, Size);
    fuzz_roaring64_bitmap_portable_deserialize_safe(Data, Size);
    fuzz_roaring_bitmap_portable_serialize(Data, Size);
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

        LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    