#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    // Declare and initialize the roaring64_bitmap_t pointers
    roaring64_bitmap_t *bitmap1 = roaring64_bitmap_create();
    roaring64_bitmap_t *bitmap2 = roaring64_bitmap_create();

    if (bitmap1 == NULL || bitmap2 == NULL) {
        // If creation failed, clean up and return
        if (bitmap1 != NULL) {
                roaring64_bitmap_free(bitmap1);
        }
        if (bitmap2 != NULL) {
                roaring64_bitmap_free(bitmap2);
        }
        return 0;
    }

    // Add some values to the bitmaps using the input data
    for (size_t i = 0; i < size; i += sizeof(uint64_t)) {
        uint64_t value = 0;
        if (i + sizeof(uint64_t) <= size) {
            value = *((uint64_t *)(data + i));
        }
        roaring64_bitmap_add(bitmap1, value);

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring64_bitmap_add to roaring64_bitmap_and_cardinality
        // Ensure dataflow is valid (i.e., non-null)
        if (!bitmap2) {
        	return 0;
        }
        size_t ret_roaring64_bitmap_shrink_to_fit_rbilg = roaring64_bitmap_shrink_to_fit(bitmap2);
        if (ret_roaring64_bitmap_shrink_to_fit_rbilg < 0){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!bitmap2) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!bitmap1) {
        	return 0;
        }

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring64_bitmap_shrink_to_fit to roaring_bitmap_deserialize_safe
        // Ensure dataflow is valid (i.e., non-null)
        if (!bitmap1) {
        	return 0;
        }
        roaring64_iterator_t* ret_roaring64_iterator_create_last_ujunh = roaring64_iterator_create_last(bitmap1);
        if (ret_roaring64_iterator_create_last_ujunh == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_roaring64_iterator_create_last_ujunh) {
        	return 0;
        }
        roaring_bitmap_t* ret_roaring_bitmap_deserialize_safe_taghs = roaring_bitmap_deserialize_safe((const void *)ret_roaring64_iterator_create_last_ujunh, ret_roaring64_bitmap_shrink_to_fit_rbilg);
        if (ret_roaring_bitmap_deserialize_safe_taghs == NULL){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
        uint64_t ret_roaring64_bitmap_and_cardinality_nhpif = roaring64_bitmap_and_cardinality(bitmap2, bitmap1);
        if (ret_roaring64_bitmap_and_cardinality_nhpif < 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
        roaring64_bitmap_add(bitmap2, value + 1); // Add offset value to bitmap2
    }

    // Call the function-under-test
    roaring64_bitmap_andnot_inplace(bitmap1, bitmap2);

    // Clean up
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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
