#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "roaring/roaring64.h"

static roaring64_bitmap_t *create_random_bitmap(const uint8_t *data, size_t size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return NULL;
    }

    for (size_t i = 0; i < size / sizeof(uint64_t); i++) {
        uint64_t value;
        memcpy(&value, data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }

    return bitmap;
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t) * 3 + 1) {
        return 0;
    }

    roaring64_bitmap_t *bitmap = create_random_bitmap(Data, Size);
    if (!bitmap) {
        return 0;
    }

    uint64_t min, max, val;
    memcpy(&min, Data, sizeof(uint64_t));
    memcpy(&max, Data + sizeof(uint64_t), sizeof(uint64_t));
    memcpy(&val, Data + 2 * sizeof(uint64_t), sizeof(uint64_t));

    // Test roaring64_bitmap_contains_range
    bool contains_range = roaring64_bitmap_contains_range(bitmap, min, max);

    // Test roaring64_bitmap_remove_checked
    bool removed = roaring64_bitmap_remove_checked(bitmap, val);

    // Test roaring64_bitmap_add_offset_signed
    bool positive = Data[3 * sizeof(uint64_t)] % 2 == 0;
    roaring64_bitmap_t *offset_bitmap = roaring64_bitmap_add_offset_signed(bitmap, positive, val);
    if (offset_bitmap) {
        roaring64_bitmap_free(offset_bitmap);
    }

    // Test roaring64_bitmap_intersect_with_range
    bool intersects = roaring64_bitmap_intersect_with_range(bitmap, min, max);

    // Test roaring64_bitmap_add
    roaring64_bitmap_add(bitmap, val);

    // Test roaring64_bitmap_range_cardinality

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring64_bitmap_add to roaring64_bitmap_jaccard_index
    // Ensure dataflow is valid (i.e., non-null)
    if (!bitmap) {
    	return 0;
    }
    bool ret_roaring64_bitmap_run_optimize_fbzwh = roaring64_bitmap_run_optimize(bitmap);
    if (ret_roaring64_bitmap_run_optimize_fbzwh == 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!bitmap) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!bitmap) {
    	return 0;
    }
    double ret_roaring64_bitmap_jaccard_index_ybxjj = roaring64_bitmap_jaccard_index(bitmap, bitmap);
    if (ret_roaring64_bitmap_jaccard_index_ybxjj < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    uint64_t cardinality = roaring64_bitmap_range_cardinality(bitmap, min, max);

    // Cleanup
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
