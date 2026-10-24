// This fuzz driver is generated for library croaring, aiming to fuzz the following functions:
// roaring_uint32_iterator_advance at roaring.c:1824:6 in roaring.h
// roaring_uint32_iterator_previous at roaring.c:1842:6 in roaring.h
// roaring_uint32_iterator_move_equalorlarger at roaring.c:1798:6 in roaring.h
// roaring_move_uint32_iterator_equalorlarger at roaring.h:1191:1 in roaring.h
// roaring_copy_uint32_iterator at roaring.h:1205:1 in roaring.h
// roaring_uint32_iterator_copy at roaring.c:1789:28 in roaring.h
// roaring_bitmap_create at roaring.h:45:26 in roaring.h
// roaring_bitmap_add at roaring.c:566:6 in roaring.h
// roaring_create_iterator at roaring.h:1143:1 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
// roaring_bitmap_free at roaring.c:552:6 in roaring.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include "roaring.h"

static void fuzz_roaring_uint32_iterator_advance(roaring_uint32_iterator_t *it) {
    while (roaring_uint32_iterator_advance(it)) {
        // Do something with it->current_value if needed
    }
}

static void fuzz_roaring_uint32_iterator_previous(roaring_uint32_iterator_t *it) {
    while (roaring_uint32_iterator_previous(it)) {
        // Do something with it->current_value if needed
    }
}

static void fuzz_roaring_uint32_iterator_move_equalorlarger(roaring_uint32_iterator_t *it, uint32_t val) {
    roaring_uint32_iterator_move_equalorlarger(it, val);
}

static void fuzz_roaring_move_uint32_iterator_equalorlarger(roaring_uint32_iterator_t *it, uint32_t val) {
    roaring_move_uint32_iterator_equalorlarger(it, val);
}

static void fuzz_roaring_copy_uint32_iterator(const roaring_uint32_iterator_t *it) {
    roaring_uint32_iterator_t *copy = roaring_copy_uint32_iterator(it);
    if (copy != NULL) {
        free(copy);
    }
}

static void fuzz_roaring_uint32_iterator_copy(const roaring_uint32_iterator_t *it) {
    roaring_uint32_iterator_t *copy = roaring_uint32_iterator_copy(it);
    if (copy != NULL) {
        free(copy);
    }
}

int LLVMFuzzerTestOneInput_76(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return 0;

    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) return 0;

    uint32_t val = *(const uint32_t *)Data;
    roaring_bitmap_add(bitmap, val);

    roaring_uint32_iterator_t *it = roaring_create_iterator(bitmap);
    if (!it) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    fuzz_roaring_uint32_iterator_advance(it);
    fuzz_roaring_uint32_iterator_previous(it);
    fuzz_roaring_uint32_iterator_move_equalorlarger(it, val);
    fuzz_roaring_move_uint32_iterator_equalorlarger(it, val);
    fuzz_roaring_copy_uint32_iterator(it);
    fuzz_roaring_uint32_iterator_copy(it);

    free(it);
    roaring_bitmap_free(bitmap);

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

        LLVMFuzzerTestOneInput_76(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    