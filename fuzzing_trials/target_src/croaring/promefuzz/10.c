// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_add at roaring64.c:423:6 in roaring64.h
// roaring64_bitmap_remove at roaring64.c:744:6 in roaring64.h
// roaring64_bitmap_add_offset_signed at roaring64.c:1959:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_or at roaring64.c:1385:21 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "roaring64.h"

static void fuzz_bitmap_operations(roaring64_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return;
    
    uint64_t value = *((uint64_t *)Data);
    Data += sizeof(uint64_t);
    Size -= sizeof(uint64_t);
    
    // Fuzz roaring64_bitmap_add
    roaring64_bitmap_add(bitmap, value);
    
    // Fuzz roaring64_bitmap_remove
    roaring64_bitmap_remove(bitmap, value);
    
    if (Size < sizeof(uint64_t)) return;
    
    uint64_t offset = *((uint64_t *)Data);
    Data += sizeof(uint64_t);
    Size -= sizeof(uint64_t);
    
    bool positive = (Size > 0) ? Data[0] % 2 : false;
    
    // Fuzz roaring64_bitmap_add_offset_signed
    roaring64_bitmap_t *offset_bitmap = roaring64_bitmap_add_offset_signed(bitmap, positive, offset);
    if (offset_bitmap) {
        roaring64_bitmap_free(offset_bitmap);
    }
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    if (!bitmap1) return 0;
    
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();
    if (!bitmap2) {
        roaring64_bitmap_free(bitmap1);
        return 0;
    }
    
    fuzz_bitmap_operations(bitmap1, Data, Size);
    fuzz_bitmap_operations(bitmap2, Data, Size);
    
    // Fuzz roaring64_bitmap_or
    roaring64_bitmap_t *or_bitmap = roaring64_bitmap_or(bitmap1, bitmap2);
    if (or_bitmap) {
        roaring64_bitmap_free(or_bitmap);
    }
    
    roaring64_bitmap_free(bitmap1);
    roaring64_bitmap_free(bitmap2);
    
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

        LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    