#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "roaring/roaring64.h"

static void initialize_context(roaring64_bulk_context_t *context) {
    memset(context, 0, sizeof(roaring64_bulk_context_t));
}

int LLVMFuzzerTestOneInput_58(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) return 0;

    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) return 0;

    size_t n_args = Size / sizeof(uint64_t);
    const uint64_t *vals = (const uint64_t *)Data;

    // Ensure that the bitmap is not empty before removal operations
    if (n_args > 0) {
        // Fuzz roaring64_bitmap_add_many
        roaring64_bitmap_add_many(bitmap, n_args, vals);

        // Fuzz roaring64_bitmap_remove_many safely
        if (roaring64_bitmap_get_cardinality(bitmap) >= n_args) {
            roaring64_bitmap_remove_many(bitmap, n_args, vals);
        }

        // Fuzz roaring64_bitmap_remove
        for (size_t i = 0; i < n_args; i++) {
            roaring64_bitmap_remove(bitmap, vals[i]);
        }

        // Fuzz roaring64_bitmap_add_bulk and roaring64_bitmap_remove_bulk
        roaring64_bulk_context_t context;
        initialize_context(&context);
        for (size_t i = 0; i < n_args; i++) {
            roaring64_bitmap_add_bulk(bitmap, &context, vals[i]);
            roaring64_bitmap_remove_bulk(bitmap, &context, vals[i]);
        }

        // Fuzz roaring64_bitmap_contains_bulk
        initialize_context(&context);
        for (size_t i = 0; i < n_args; i++) {
            roaring64_bitmap_contains_bulk(bitmap, &context, vals[i]);
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

    LLVMFuzzerTestOneInput_58(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
