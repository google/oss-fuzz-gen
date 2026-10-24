// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring64_bitmap_create at roaring64.c:225:21 in roaring64.h
// roaring64_bitmap_add_range at roaring64.c:510:6 in roaring64.h
// roaring64_bitmap_remove_range at roaring64.c:847:6 in roaring64.h
// roaring64_bitmap_remove at roaring64.c:744:6 in roaring64.h
// roaring64_bitmap_remove_range_closed at roaring64.c:855:6 in roaring64.h
// roaring64_bitmap_add_offset at roaring64.h:543:35 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_sub_offset at roaring64.h:554:35 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
// roaring64_bitmap_free at roaring64.c:236:6 in roaring64.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "roaring64.h"

static uint64_t read_uint64(const uint8_t *Data, size_t *offset, size_t Size) {
    if (*offset + sizeof(uint64_t) > Size) {
        *offset = Size;
        return 0;
    }
    uint64_t value;
    memcpy(&value, Data + *offset, sizeof(uint64_t));
    *offset += sizeof(uint64_t);
    return value;
}

int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    size_t offset = 0;
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return 0;

    while (offset < Size) {
        uint8_t action = Data[offset++];
        uint64_t val1 = read_uint64(Data, &offset, Size);
        uint64_t val2 = read_uint64(Data, &offset, Size);

        switch (action % 6) {
            case 0:
                roaring64_bitmap_add_range(bitmap, val1, val2);
                break;
            case 1:
                roaring64_bitmap_remove_range(bitmap, val1, val2);
                break;
            case 2:
                roaring64_bitmap_remove(bitmap, val1);
                break;
            case 3:
                roaring64_bitmap_remove_range_closed(bitmap, val1, val2);
                break;
            case 4: {
                roaring64_bitmap_t *new_bitmap = roaring64_bitmap_add_offset(bitmap, val1);
                if (new_bitmap) {
                    roaring64_bitmap_free(new_bitmap);
                }
                break;
            }
            case 5: {
                roaring64_bitmap_t *new_bitmap = roaring64_bitmap_sub_offset(bitmap, val1);
                if (new_bitmap) {
                    roaring64_bitmap_free(new_bitmap);
                }
                break;
            }
            default:
                break;
        }
    }

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

        LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    