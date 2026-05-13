#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "roaring/roaring.h"

static void fuzz_roaring_bitmap_portable_deserialize_safe(const uint8_t *Data, size_t Size) {
    if (Size < 4) {
        return;
    } // Minimum size to attempt deserialization

    roaring_bitmap_t *bitmap = roaring_bitmap_portable_deserialize_safe((const char *)Data, Size);
    if (bitmap != NULL) {
        roaring_bitmap_free(bitmap);
    }
}

static void fuzz_roaring_bitmap_serialize(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_portable_deserialize_safe((const char *)Data, Size);
    if (bitmap == NULL) {
        return;
    }

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
    if (bitmap == NULL) {
        return;
    }

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
    if (Size < 4) {
        return;
    } // Minimum size to attempt deserialization

    roaring_bitmap_t *bitmap = roaring_bitmap_deserialize_safe((const void *)Data, Size);
    if (bitmap != NULL) {
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function roaring_bitmap_free with roaring_bitmap_printf_describe
        roaring_bitmap_printf_describe(bitmap);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
    }
}

int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size) {
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

    LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
