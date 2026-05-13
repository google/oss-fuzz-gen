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

int LLVMFuzzerTestOneInput_46(const uint8_t *Data, size_t Size) {
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

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from roaring64_bitmap_portable_size_in_bytes to roaring_bitmap_from_range
    const roaring_bitmap_t sjasjnwi;
    memset(&sjasjnwi, 0, sizeof(sjasjnwi));
    uint32_t ret_roaring_bitmap_maximum_bbdun = roaring_bitmap_maximum(&sjasjnwi);
    if (ret_roaring_bitmap_maximum_bbdun < 0){
    	return 0;
    }
    const roaring_bitmap_t jsldbpra;
    memset(&jsldbpra, 0, sizeof(jsldbpra));
    size_t ret_roaring_bitmap_portable_size_in_bytes_aincz = roaring_bitmap_portable_size_in_bytes(&jsldbpra);
    if (ret_roaring_bitmap_portable_size_in_bytes_aincz < 0){
    	return 0;
    }
    roaring_bitmap_t* ret_roaring_bitmap_from_range_rwfxe = roaring_bitmap_from_range((uint64_t )ret_roaring_bitmap_maximum_bbdun, (uint64_t )buffer_size, (uint32_t )ret_roaring_bitmap_portable_size_in_bytes_aincz);
    if (ret_roaring_bitmap_from_range_rwfxe == NULL){
    	return 0;
    }
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

    LLVMFuzzerTestOneInput_46(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
