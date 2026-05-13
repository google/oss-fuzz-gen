#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <aom/aom_image.h> // Assuming this is the correct header for aom_img_metadata_alloc

extern "C" {
    aom_metadata_t * aom_img_metadata_alloc(uint32_t type, const uint8_t *data, size_t data_size, aom_metadata_insert_flags_t flags);
}

extern "C" int LLVMFuzzerTestOneInput_12(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for our needs
    if (size < sizeof(uint32_t) + sizeof(aom_metadata_insert_flags_t) + 1) {
        return 0;
    }

    // Extract a uint32_t type from the data
    uint32_t type = *(reinterpret_cast<const uint32_t*>(data));
    data += sizeof(uint32_t);
    size -= sizeof(uint32_t);

    // Extract aom_metadata_insert_flags_t flags from the data
    aom_metadata_insert_flags_t flags = *(reinterpret_cast<const aom_metadata_insert_flags_t*>(data));
    data += sizeof(aom_metadata_insert_flags_t);
    size -= sizeof(aom_metadata_insert_flags_t);

    // Use the remaining data as the metadata
    const uint8_t *metadata = data;
    size_t metadata_size = size;

    // Call the function under test
    aom_metadata_t *metadata_result = aom_img_metadata_alloc(type, metadata, metadata_size, flags);

    // Clean up if necessary
    if (metadata_result != NULL) {
        // Assuming there's a function to free the metadata
        // aom_img_metadata_free(metadata_result); // Uncomment if such a function exists
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

    LLVMFuzzerTestOneInput_12(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
