#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "roaring/roaring.h"

static roaring_bitmap_t *create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring_bitmap_t *bitmap = roaring_bitmap_create();
    if (!bitmap) {
        return NULL;
    }

    for (size_t i = 0; i < Size; i++) {
        uint32_t value = (uint32_t)Data[i];
        roaring_bitmap_add(bitmap, value);
    
        // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring_bitmap_add to roaring_bitmap_lazy_xor
        roaring_bitmap_t* ret_roaring_bitmap_of_jjnqz = roaring_bitmap_of(1);
        if (ret_roaring_bitmap_of_jjnqz == NULL){
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!ret_roaring_bitmap_of_jjnqz) {
        	return 0;
        }
        // Ensure dataflow is valid (i.e., non-null)
        if (!bitmap) {
        	return 0;
        }
        roaring_bitmap_t* ret_roaring_bitmap_lazy_xor_kdpae = roaring_bitmap_lazy_xor(ret_roaring_bitmap_of_jjnqz, bitmap);
        if (ret_roaring_bitmap_lazy_xor_kdpae == NULL){
        	return 0;
        }
        // End mutation: Producer.APPEND_MUTATOR
        
}
    return bitmap;
}

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    if (Size < 1) {
        return 0;
    }

    roaring_bitmap_t *bitmap = create_random_bitmap(Data, Size);
    if (!bitmap) {
        return 0;
    }

    roaring_uint32_iterator_t *iterator = roaring_iterator_create(bitmap);
    if (iterator) {
        roaring_uint32_iterator_t *copy_iterator = roaring_uint32_iterator_copy(iterator);
        if (copy_iterator) {
            roaring_uint32_iterator_free(copy_iterator);
        }

        roaring_free_uint32_iterator(iterator);
    }

    roaring_uint32_iterator_t new_iterator;
    roaring_init_iterator(bitmap, &new_iterator);

    roaring_bitmap_free(bitmap);

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

    LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
