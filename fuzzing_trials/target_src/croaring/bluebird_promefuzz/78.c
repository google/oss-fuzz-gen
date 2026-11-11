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
#include "roaring/roaring64.h"

static roaring64_bitmap_t* create_random_bitmap(const uint8_t *Data, size_t Size) {
    roaring64_bitmap_t *bitmap = roaring64_bitmap_create();
    if (!bitmap) {
        return NULL;
    }

    for (size_t i = 0; i < Size / sizeof(uint64_t); ++i) {
        uint64_t value;
        memcpy(&value, Data + i * sizeof(uint64_t), sizeof(uint64_t));
        roaring64_bitmap_add(bitmap, value);
    }
    return bitmap;
}

int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint64_t)) {
        return 0;
    }

    roaring64_bitmap_t *bitmap = create_random_bitmap(Data, Size);
    if (!bitmap) {
        return 0;
    }

    uint64_t value;
    memcpy(&value, Data, sizeof(uint64_t));

    // Test roaring64_bitmap_remove
    roaring64_bitmap_remove(bitmap, value);

    // Test roaring64_bitmap_portable_serialize and roaring64_bitmap_portable_size_in_bytes
    size_t buffer_size = roaring64_bitmap_portable_size_in_bytes(bitmap);

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring64_bitmap_portable_size_in_bytes to roaring_bitmap_flip_inplace
    roaring_bitmap_t* ret_roaring_bitmap_create_with_capacity_ioilw = roaring_bitmap_create_with_capacity(-1);
    if (ret_roaring_bitmap_create_with_capacity_ioilw == NULL){
    	return 0;
    }
    const roaring_bitmap_t avfbrldr;
    memset(&avfbrldr, 0, sizeof(avfbrldr));
    uint32_t ret_roaring_bitmap_maximum_jidli = roaring_bitmap_maximum(&avfbrldr);
    if (ret_roaring_bitmap_maximum_jidli < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!ret_roaring_bitmap_create_with_capacity_ioilw) {
    	return 0;
    }
    roaring_bitmap_flip_inplace(ret_roaring_bitmap_create_with_capacity_ioilw, (uint64_t )buffer_size, (uint64_t )ret_roaring_bitmap_maximum_jidli);
    // End mutation: Producer.APPEND_MUTATOR
    
    char *buffer = (char *)malloc(buffer_size);
    if (buffer) {
        size_t serialized_size = roaring64_bitmap_portable_serialize(bitmap, buffer);

        // Test roaring64_bitmap_portable_deserialize_safe
        roaring64_bitmap_t *deserialized_bitmap = roaring64_bitmap_portable_deserialize_safe(buffer, serialized_size);
        if (deserialized_bitmap) {
            roaring64_bitmap_free(deserialized_bitmap);
        }

        free(buffer);
    }

    // Test roaring64_bitmap_frozen_serialize and roaring64_bitmap_frozen_view
    roaring64_bitmap_shrink_to_fit(bitmap);
    size_t frozen_size = roaring64_bitmap_frozen_size_in_bytes(bitmap);
    buffer = (char *)malloc(frozen_size);
    if (buffer) {
        size_t frozen_serialized_size = roaring64_bitmap_frozen_serialize(bitmap, buffer);
        roaring64_bitmap_t *frozen_view = roaring64_bitmap_frozen_view(buffer, frozen_serialized_size);
        if (frozen_view) {
            roaring64_bitmap_free(frozen_view);
        }
        free(buffer);
    }

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

    LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
