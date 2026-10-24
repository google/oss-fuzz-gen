#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include "roaring/roaring.h"

static roaring_bitmap_t* create_bitmap_from_data(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) return NULL;
    size_t num_elements = Size / sizeof(uint32_t);
    uint32_t *elements = (uint32_t *)Data;

    // Ensure we do not access more elements than available
    if (num_elements > 5) num_elements = 5;

    switch (num_elements) {
        case 5: return roaring_bitmap_of(5, elements[0], elements[1], elements[2], elements[3], elements[4]);
        case 4: return roaring_bitmap_of(4, elements[0], elements[1], elements[2], elements[3]);
        case 3: return roaring_bitmap_of(3, elements[0], elements[1], elements[2]);
        case 2: return roaring_bitmap_of(2, elements[0], elements[1]);
        case 1: return roaring_bitmap_of(1, elements[0]);
        default: return NULL;
    }
}

int LLVMFuzzerTestOneInput_49(const uint8_t *Data, size_t Size) {
    // Fuzz roaring_bitmap_of
    roaring_bitmap_t *bitmap1 = create_bitmap_from_data(Data, Size);
    roaring_bitmap_t *bitmap2 = create_bitmap_from_data(Data, Size);

    if (bitmap1 == NULL || bitmap2 == NULL) {
        roaring_bitmap_free(bitmap1);
        roaring_bitmap_free(bitmap2);
        return 0;
    }

    // Fuzz roaring_bitmap_or
    roaring_bitmap_t *bitmap_or = roaring_bitmap_or(bitmap1, bitmap2);
    roaring_bitmap_free(bitmap_or);

    // Fuzz roaring_bitmap_copy
    roaring_bitmap_t *bitmap_copy = roaring_bitmap_copy(bitmap1);
    roaring_bitmap_free(bitmap_copy);

    // Prepare an array of bitmaps for XOR operation
    const roaring_bitmap_t *bitmaps[] = {bitmap1, bitmap2};
    size_t number_of_bitmaps = 2;

    // Fuzz roaring_bitmap_xor_many
    roaring_bitmap_t *bitmap_xor = roaring_bitmap_xor_many(number_of_bitmaps, bitmaps);
    roaring_bitmap_free(bitmap_xor);

    // Fuzz roaring_bitmap_or_cardinality
    uint64_t cardinality = roaring_bitmap_or_cardinality(bitmap1, bitmap2);
    (void)cardinality; // Suppress unused variable warning

    // Fuzz roaring_bitmap_deserialize_safe
    roaring_bitmap_t *deserialized_bitmap = roaring_bitmap_deserialize_safe(Data, Size);
    roaring_bitmap_free(deserialized_bitmap);

    // Clean up
    roaring_bitmap_free(bitmap1);
    roaring_bitmap_free(bitmap2);

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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
