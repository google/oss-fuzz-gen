#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "roaring/roaring.h"
#include "/src/croaring/include/roaring/containers/run.h"
#include "/src/croaring/include/roaring/containers/containers.h"
#include "/src/croaring/include/roaring/memory.h"

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract an int64_t
    if (size < sizeof(int64_t)) {
        return 0;
    }

    // Create a roaring bitmap
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (bitmap == NULL) {
        return 0;
    }

    // Add some elements to the bitmap to ensure it is not empty
    for (uint32_t i = 0; i < 100; i++) {
        roaring_bitmap_add(bitmap, i);
    }

    // Extract an int64_t value from the input data
    int64_t offset;
    memcpy(&offset, data, sizeof(int64_t));

    // Call the function-under-test
    roaring_bitmap_t *result = roaring_bitmap_add_offset(bitmap, offset);

    // Clean up

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring_bitmap_add_offset to roaring_bitmap_andnot_cardinality
    // Ensure dataflow is valid (i.e., non-null)
    if (!result) {
    	return 0;
    }
    size_t ret_roaring_bitmap_shrink_to_fit_ohjhc = roaring_bitmap_shrink_to_fit(result);
    if (ret_roaring_bitmap_shrink_to_fit_ohjhc < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!result) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!result) {
    	return 0;
    }
    uint64_t ret_roaring_bitmap_andnot_cardinality_uhngd = roaring_bitmap_andnot_cardinality(result, result);
    if (ret_roaring_bitmap_andnot_cardinality_uhngd < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    roaring_bitmap_free(bitmap);
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
