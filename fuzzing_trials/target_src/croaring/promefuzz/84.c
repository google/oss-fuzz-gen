// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_portable_deserialize_size at roaring64.c:2236:8 in roaring64.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_portable_size_in_bytes at roaring64.c:2106:8 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_portable_deserialize_safe at roaring64.c:2282:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_frozen_view at roaring64.c:2609:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring_bitmap_portable_deserialize_size at roaring.c:1567:8 in roaring.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_portable_size_in_bytes at roaring64.c:2106:8 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_portable_serialize at roaring64.c:2167:8 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "roaring64.h"
#include "roaring.h"

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

int LLVMFuzzerTestOneInput_84(const uint8_t *Data, size_t Size) {
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

        LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    