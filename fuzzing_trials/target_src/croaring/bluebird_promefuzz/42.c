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
#include "roaring/roaring64.h"
#include "roaring/roaring.h"

static void fuzz_roaring64_bitmap_portable_deserialize_size(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;
    
    size_t maxbytes = *(size_t *)Data;
    if (maxbytes > Size - sizeof(size_t)) return;

    size_t result = roaring64_bitmap_portable_deserialize_size((const char *)Data + sizeof(size_t), maxbytes);
    (void)result;
}

static void fuzz_roaring64_bitmap_portable_size_in_bytes() {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return;

    size_t size = roaring64_bitmap_portable_size_in_bytes(bitmap);
    (void)size;

    roaring64_bitmap_free(bitmap);
}

static void fuzz_roaring64_bitmap_portable_deserialize_safe(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;

    size_t maxbytes = *(size_t *)Data;
    if (maxbytes > Size - sizeof(size_t)) return;

    roaring64_bitmap_t *bitmap = roaring64_bitmap_portable_deserialize_safe((const char *)Data + sizeof(size_t), maxbytes);
    if (bitmap) {
        roaring64_bitmap_free(bitmap);
    }
}

static void fuzz_roaring64_bitmap_frozen_view(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;

    size_t maxbytes = *(size_t *)Data;
    if (maxbytes > Size - sizeof(size_t)) return;

    roaring64_bitmap_t *bitmap = roaring64_bitmap_frozen_view((const char *)Data + sizeof(size_t), maxbytes);
    if (bitmap) {
        roaring64_bitmap_free(bitmap);
    }
}

static void fuzz_roaring_bitmap_portable_deserialize_size(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(size_t)) return;

    size_t maxbytes = *(size_t *)Data;
    if (maxbytes > Size - sizeof(size_t)) return;

    size_t result = roaring_bitmap_portable_deserialize_size((const char *)Data + sizeof(size_t), maxbytes);
    (void)result;
}

static void fuzz_roaring64_bitmap_portable_serialize(const uint8_t *Data, size_t Size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return;

    size_t buf_size = roaring64_bitmap_portable_size_in_bytes(bitmap);
    if (Size < buf_size) {
        roaring64_bitmap_free(bitmap);
        return;
    }

    char *buf = (char *)malloc(buf_size);
    if (!buf) {
        roaring64_bitmap_free(bitmap);
        return;
    }

    size_t written = roaring64_bitmap_portable_serialize(bitmap, buf);
    (void)written;

    free(buf);
    roaring64_bitmap_free(bitmap);
}

int LLVMFuzzerTestOneInput_42(const uint8_t *Data, size_t Size) {
    fuzz_roaring64_bitmap_portable_deserialize_size(Data, Size);
    fuzz_roaring64_bitmap_portable_size_in_bytes();
    fuzz_roaring64_bitmap_portable_deserialize_safe(Data, Size);
    fuzz_roaring64_bitmap_frozen_view(Data, Size);
    fuzz_roaring_bitmap_portable_deserialize_size(Data, Size);
    fuzz_roaring64_bitmap_portable_serialize(Data, Size);
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

    LLVMFuzzerTestOneInput_42(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
