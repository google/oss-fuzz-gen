#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "roaring/roaring.h"

static uint32_t *generate_random_uint32_array(const uint8_t *data, size_t size, size_t *out_count) {
    if (size < sizeof(uint32_t)) {
        *out_count = 0;
        return NULL;
    }
    size_t count = size / sizeof(uint32_t);
    uint32_t *array = (uint32_t *)malloc(count * sizeof(uint32_t));
    if (!array) {
        *out_count = 0;
        return NULL;
    }
    memcpy(array, data, count * sizeof(uint32_t));
    *out_count = count;
    return array;
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    size_t count;
    uint32_t *vals = generate_random_uint32_array(Data, Size, &count);

    if (!vals) {
        return 0;
    }

    // Test roaring_bitmap_of_ptr
    roaring_bitmap_t *bitmap = roaring_bitmap_of_ptr(count, vals);
    if (!bitmap) {
        free(vals);
        return 0;
    }

    // Test roaring_bitmap_add_range_closed
    if (count >= 2) {
        uint32_t min = vals[0];
        uint32_t max = vals[1];
        roaring_bitmap_add_range_closed(bitmap, min, max);
    }

    // Test roaring_bitmap_or_many_heap
    const roaring_bitmap_t *bitmaps[] = {bitmap};
    roaring_bitmap_t *union_bitmap = roaring_bitmap_or_many_heap(1, bitmaps);
    if (union_bitmap) {
        roaring_bitmap_free(union_bitmap);
    }

    // Test roaring_bitmap_select
    uint32_t element;
    if (roaring_bitmap_select(bitmap, 0, &element)) {
        // element successfully selected
    }

    // Test roaring_bitmap_contains_range_closed
    if (count >= 2) {
        uint32_t range_start = vals[0];
        uint32_t range_end = vals[1];
        roaring_bitmap_contains_range_closed(bitmap, range_start, range_end);
    }

    // Test roaring_bitmap_remove_many

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring_bitmap_select to roaring64_bitmap_remove_range
    // Ensure dataflow is valid (i.e., non-null)
    if (!bitmap) {
    	return 0;
    }
    roaring64_bitmap_t* ret_roaring64_bitmap_move_from_roaring32_omxyo = roaring64_bitmap_move_from_roaring32(bitmap);
    if (ret_roaring64_bitmap_move_from_roaring32_omxyo == NULL){
    	return 0;
    }
    const roaring_bitmap_t rieewdxd;
    memset(&rieewdxd, 0, sizeof(rieewdxd));
    size_t ret_roaring_bitmap_frozen_size_in_bytes_oqbiw = roaring_bitmap_frozen_size_in_bytes(&rieewdxd);
    if (ret_roaring_bitmap_frozen_size_in_bytes_oqbiw < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_roaring64_bitmap_move_from_roaring32_omxyo) {
    	return 0;
    }
    roaring64_bitmap_remove_range(ret_roaring64_bitmap_move_from_roaring32_omxyo, (uint64_t )element, (uint64_t )ret_roaring_bitmap_frozen_size_in_bytes_oqbiw);
    // End mutation: Producer.APPEND_MUTATOR
    
    roaring_bitmap_remove_many(bitmap, count, vals);

    // Cleanup
    roaring_bitmap_free(bitmap);
    free(vals);

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
