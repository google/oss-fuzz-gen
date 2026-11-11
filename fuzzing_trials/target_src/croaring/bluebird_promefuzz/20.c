#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "roaring/roaring64.h"

static void initialize_bitmap_with_random_data(roaring64_bitmap_t *bitmap, const uint8_t *Data, size_t Size) {
    size_t num_elements = Size / sizeof(uint64_t);
    if (num_elements > 0) {
        uint64_t *values = (uint64_t *)malloc(num_elements * sizeof(uint64_t));
        if (values == NULL) return;
        memcpy(values, Data, num_elements * sizeof(uint64_t));
        roaring64_bitmap_add_many(bitmap, num_elements, values);
        free(values);
    }
}

int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) {
        return 0; // Not enough data to proceed
    }

    // Create a bitmap from a range
    uint64_t min = 0;
    uint64_t max = 1000;
    uint64_t step = 1;
    roaring64_bitmap_t *bitmap = roaring64_bitmap_from_range(min, max, step);
    if (!bitmap) {
        return 0;
    }

    // Initialize bitmap with random data
    initialize_bitmap_with_random_data(bitmap, Data, Size);

    // Use the first uint64_t value from data to test removal functions
    uint64_t test_value = *(const uint64_t *)Data;

    // Test roaring64_bitmap_remove_checked
    bool removed_checked = roaring64_bitmap_remove_checked(bitmap, test_value);
    if (removed_checked) {
        roaring64_bitmap_add(bitmap, test_value); // Re-add for further testing
    }

    // Test roaring64_bitmap_remove
    roaring64_bitmap_remove(bitmap, test_value);
    roaring64_bitmap_add(bitmap, test_value); // Re-add for further testing

    // Test roaring64_bitmap_remove_many
    size_t num_elements = Size / sizeof(uint64_t);
    if (num_elements > 0) {
        uint64_t *values = (uint64_t *)malloc(num_elements * sizeof(uint64_t));
        if (values != NULL) {
            memcpy(values, Data, num_elements * sizeof(uint64_t));
            // Ensure the values are within the valid range of the bitmap
            for (size_t i = 0; i < num_elements; i++) {
                values[i] = values[i] % max;
            }
            roaring64_bitmap_remove_many(bitmap, num_elements, values);
            free(values);
        }
    }

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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
