#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "roaring/roaring.h"

static roaring_bitmap_t *create_random_bitmap(const uint8_t *data, size_t size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) {
        return NULL;
    }
    
    for (size_t i = 0; i < size / sizeof(uint32_t); i++) {
        uint32_t value;
        memcpy(&value, data + i * sizeof(uint32_t), sizeof(uint32_t));
        roaring_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_52(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return 0;
    }

    // Divide the input data into two parts for two bitmaps
    size_t half_size = Size / 2;

    roaring_bitmap_t *r1 = create_random_bitmap(Data, half_size);
    roaring_bitmap_t *r2 = create_random_bitmap(Data + half_size, Size - half_size);

    if (!r1 || !r2) {
        goto cleanup;
    }

    // Fuzzing roaring_bitmap_xor_inplace
    roaring_bitmap_xor_inplace(r1, r2);

    // Fuzzing roaring_bitmap_lazy_xor_inplace
    roaring_bitmap_lazy_xor_inplace(r1, r2);

    // Fuzzing roaring_bitmap_and_inplace
    roaring_bitmap_and_inplace(r1, r2);

    // Fuzzing roaring_bitmap_lazy_or_inplace
    roaring_bitmap_lazy_or_inplace(r1, r2, true);

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring_bitmap_lazy_or_inplace to roaring_bitmap_and_cardinality
    const char milvvxxb[1024] = "djtva";
    roaring_bitmap_t* ret_roaring_bitmap_portable_deserialize_frozen_lwrjd = roaring_bitmap_portable_deserialize_frozen(milvvxxb);
    if (ret_roaring_bitmap_portable_deserialize_frozen_lwrjd == NULL){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_roaring_bitmap_portable_deserialize_frozen_lwrjd) {
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!r1) {
    	return 0;
    }
    uint64_t ret_roaring_bitmap_and_cardinality_uoiha = roaring_bitmap_and_cardinality(ret_roaring_bitmap_portable_deserialize_frozen_lwrjd, r1);
    if (ret_roaring_bitmap_and_cardinality_uoiha < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    
    roaring_bitmap_lazy_or_inplace(r1, r2, false);

    // Fuzzing roaring_bitmap_or_inplace
    roaring_bitmap_or_inplace(r1, r2);

    // Fuzzing roaring_bitmap_andnot_inplace
    roaring_bitmap_andnot_inplace(r1, r2);

cleanup:
    if (r1) {
        roaring_bitmap_free(r1);
    }
    if (r2) {
        roaring_bitmap_free(r2);
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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
