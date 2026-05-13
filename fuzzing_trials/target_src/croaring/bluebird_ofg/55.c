#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "roaring/roaring.h"
#include "/src/croaring/include/roaring/containers/run.h"
#include "/src/croaring/include/roaring/containers/containers.h"
#include "/src/croaring/include/roaring/memory.h"

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
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
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring_bitmap_add to roaring_bitmap_equals
        // Ensure dataflow is valid (i.e., non-null)
        if (!bitmap) {
        	return 0;
        }
        bool ret_roaring_bitmap_remove_run_compression_qtzej = roaring_bitmap_remove_run_compression(bitmap);
        if (ret_roaring_bitmap_remove_run_compression_qtzej == 0){
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
        bool ret_roaring_bitmap_equals_tsgrt = roaring_bitmap_equals(bitmap, bitmap);
        if (ret_roaring_bitmap_equals_tsgrt == 0){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
}

    // Extract an int64_t value from the input data
    int64_t offset;
    memcpy(&offset, data, sizeof(int64_t));

    // Call the function-under-test
    roaring_bitmap_t *result = roaring_bitmap_add_offset(bitmap, offset);

    // Clean up
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

    LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
