#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "roaring/roaring.h"

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Check if the size is sufficient to create at least one bitmap
    if (size < sizeof(uint32_t)) {
        return 0;
    }
    
    // Calculate the number of bitmaps to create
    size_t num_bitmaps = size / sizeof(uint32_t);
    if (num_bitmaps < 1) {
        return 0;
    }

    // Allocate memory for the array of bitmap pointers
    const roaring_bitmap_t **bitmaps = (const roaring_bitmap_t **)malloc(num_bitmaps * sizeof(roaring_bitmap_t *));
    if (bitmaps == NULL) {
        return 0;
    }

    // Initialize each bitmap with data from the input
    for (size_t i = 0; i < num_bitmaps; i++) {
        // Create a new bitmap
        roaring_bitmap_t *bitmap = roaring_bitmap_create();
        if (bitmap == NULL) {
            // Free already allocated bitmaps in case of failure
            for (size_t j = 0; j < i; j++) {
                roaring_bitmap_free((roaring_bitmap_t *)bitmaps[j]);
            }
            free(bitmaps);
            return 0;
        }

        // Add a value to the bitmap to ensure it's not empty
        uint32_t value = *((uint32_t *)(data + i * sizeof(uint32_t)));
        roaring_bitmap_add(bitmap, value);

        // Assign the bitmap to the array

        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring_bitmap_add to roaring_bitmap_and_inplace
        roaring_bitmap_t* ret_roaring_bitmap_of_sboem = roaring_bitmap_of(64);
        if (ret_roaring_bitmap_of_sboem == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_roaring_bitmap_of_sboem) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!bitmap) {
        	return 0;
        }
        roaring_bitmap_and_inplace(ret_roaring_bitmap_of_sboem, bitmap);
        // End mutation: Producer.APPEND_MUTATOR
        
        bitmaps[i] = bitmap;
    }

    // Call the function-under-test
    roaring_bitmap_t *result = roaring_bitmap_or_many(num_bitmaps, bitmaps);

    // Free the allocated bitmaps
    for (size_t i = 0; i < num_bitmaps; i++) {
        roaring_bitmap_free((roaring_bitmap_t *)bitmaps[i]);
    }
    free(bitmaps);

    // Free the result bitmap
    if (result != NULL) {
        roaring_bitmap_free(result);
    }

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

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
