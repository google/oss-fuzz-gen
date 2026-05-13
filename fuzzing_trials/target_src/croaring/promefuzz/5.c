// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_bitmap_portable_deserialize_safe at roaring.c:1541:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_portable_deserialize_safe at roaring.c:1541:19 in roaring.h
// roaring_bitmap_size_in_bytes at roaring.c:1529:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_serialize at roaring.c:1513:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_portable_deserialize_safe at roaring.c:1541:19 in roaring.h
// roaring_bitmap_portable_size_in_bytes at roaring.c:1537:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_portable_serialize at roaring.c:1572:8 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_deserialize_safe at roaring.c:1606:19 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "roaring.h"

static void fuzz_roaring_bitmap_portable_deserialize_safe(const uint8_t *Data, size_t Size) {
    if (Size < 4) return; // Minimum size to attempt deserialization

    roaring_bitmap_t *bitmap = roaring_bitmap_portable_deserialize_safe((const char *)Data, Size);
    if (bitmap != NULL) {
        roaring_bitmap_free(bitmap);
    }
}

static void fuzz_roaring_bitmap_serialize(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_portable_deserialize_safe((const char *)Data, Size);
    if (bitmap == NULL) return;

    size_t required_size = roaring_bitmap_size_in_bytes(bitmap);
    char *buffer = (char *)malloc(required_size);
    if (buffer == NULL) {
        roaring_bitmap_free(bitmap);
        return;
    }

    size_t bytes_written = roaring_bitmap_serialize(bitmap, buffer);
    (void)bytes_written; // Suppress unused variable warning

    free(buffer);
    roaring_bitmap_free(bitmap);
}

static void fuzz_roaring_bitmap_portable_serialize(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_portable_deserialize_safe((const char *)Data, Size);
    if (bitmap == NULL) return;

    size_t required_size = roaring_bitmap_portable_size_in_bytes(bitmap);
    char *buffer = (char *)malloc(required_size);
    if (buffer == NULL) {
        roaring_bitmap_free(bitmap);
        return;
    }

    size_t bytes_written = roaring_bitmap_portable_serialize(bitmap, buffer);
    (void)bytes_written; // Suppress unused variable warning

    free(buffer);
    roaring_bitmap_free(bitmap);
}

static void fuzz_roaring_bitmap_deserialize_safe(const uint8_t *Data, size_t Size) {
    if (Size < 4) return; // Minimum size to attempt deserialization

    roaring_bitmap_t *bitmap = roaring_bitmap_deserialize_safe((const void *)Data, Size);
    if (bitmap != NULL) {
        roaring_bitmap_free(bitmap);
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    fuzz_roaring_bitmap_portable_deserialize_safe(Data, Size);
    fuzz_roaring_bitmap_serialize(Data, Size);
    fuzz_roaring_bitmap_portable_serialize(Data, Size);
    fuzz_roaring_bitmap_deserialize_safe(Data, Size);

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
    