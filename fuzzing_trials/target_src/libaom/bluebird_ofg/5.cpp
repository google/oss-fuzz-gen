#include <string.h>
#include <sys/stat.h>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "/src/aom/aom/aom_image.h"
#include "/src/aom/aom/aom_codec.h"

extern "C" int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Initialize variables for the function parameters
    aom_image_t img;
    uint32_t type;
    const uint8_t *metadata;
    size_t metadata_size;
    aom_metadata_insert_flags_t flags;

    // Ensure the size is large enough to extract meaningful data
    if (size < sizeof(uint32_t) + sizeof(aom_metadata_insert_flags_t) + 1) {
        return 0;
    }

    // Initialize the image
    memset(&img, 0, sizeof(aom_image_t));

    // Extract type from data
    type = *(reinterpret_cast<const uint32_t *>(data));
    data += sizeof(uint32_t);
    size -= sizeof(uint32_t);

    // Extract flags from data
    flags = *(reinterpret_cast<const aom_metadata_insert_flags_t *>(data));
    data += sizeof(aom_metadata_insert_flags_t);
    size -= sizeof(aom_metadata_insert_flags_t);

    // Remaining data is used as metadata
    metadata = data;
    metadata_size = size;

    // Call the function-under-test
    aom_img_add_metadata(&img, type, metadata, metadata_size, flags);

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
