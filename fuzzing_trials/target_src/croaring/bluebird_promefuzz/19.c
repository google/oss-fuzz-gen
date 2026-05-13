#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "roaring/roaring64.h"
#include "roaring/roaring.h"

static bool dummy_iterator(uint64_t value, void *param) {
    return true;
}

int LLVMFuzzerTestOneInput_19(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) {
        return 0;
    }

    // Create a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) {
        return 0;
    }

    // Add some data to the bitmap
    for (size_t i = 0; i < Size / sizeof(uint32_t); ++i) {
        uint32_t val;
        memcpy(&val, Data + i * sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_add(bitmap, val);
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring_bitmap_add to roaring_bitmap_jaccard_index
        roaring_bitmap_t* ret_roaring_bitmap_of_rucgm = roaring_bitmap_of(1);
        if (ret_roaring_bitmap_of_rucgm == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_roaring_bitmap_of_rucgm) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!bitmap) {
        	return 0;
        }
        double ret_roaring_bitmap_jaccard_index_nsnoa = roaring_bitmap_jaccard_index(ret_roaring_bitmap_of_rucgm, bitmap);
        if (ret_roaring_bitmap_jaccard_index_nsnoa < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
}

    // Create a roaring64 bitmap
    roaring64_bitmap_t *bitmap64 = roaring64_bitmap_create();
    if (!bitmap64) {
        roaring_bitmap_free(bitmap);
        return 0;
    }

    // Add some data to the roaring64 bitmap
    for (size_t i = 0; i < Size / sizeof(uint64_t); ++i) {
        uint64_t val;
        memcpy(&val, Data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap64, val);
    }

    // Test roaring_iterate64
    uint64_t high_bits = 0;
    roaring_iterate64(bitmap, dummy_iterator, high_bits, NULL);

    // Initialize an iterator
    roaring64_iterator_t *iterator = roaring64_iterator_create(bitmap64);

    if (iterator != NULL) {
        // Test roaring64_iterator_move_equalorlarger
        uint64_t target_val;
        memcpy(&target_val, Data, sizeof(uint64_t));
        roaring64_iterator_move_equalorlarger(iterator, target_val);

        // Test roaring64_iterator_advance
        roaring64_iterator_advance(iterator);

        // Test roaring64_iterator_reinit_last
        roaring64_iterator_reinit_last(bitmap64, iterator);

        // Test roaring64_iterator_read
        uint64_t buf[10];
        roaring64_iterator_read(iterator, buf, 10);

        // Test roaring64_iterator_value
        if (roaring64_iterator_has_value(iterator)) {
            roaring64_iterator_value(iterator);
        }

        // Free the iterator
        roaring64_iterator_free(iterator);
    }

    // Cleanup
    roaring_bitmap_free(bitmap);
    roaring64_bitmap_free(bitmap64);

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

    LLVMFuzzerTestOneInput_19(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
