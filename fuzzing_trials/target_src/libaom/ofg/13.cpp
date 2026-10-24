#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <aom/aom_image.h>

extern "C" {
    aom_metadata_t * aom_img_metadata_alloc(uint32_t type, const uint8_t *data, size_t data_size, aom_metadata_insert_flags_t flags);
}

extern "C" int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for aom_img_metadata_alloc
    uint32_t type = 1; // Example type, can be varied
    const uint8_t *metadata_data = data; // Use the input data as metadata
    size_t data_size = size; // Size of the input data
    aom_metadata_insert_flags_t flags = static_cast<aom_metadata_insert_flags_t>(0); // Example flag, can be varied

    // Call the function-under-test
    aom_metadata_t *metadata = aom_img_metadata_alloc(type, metadata_data, data_size, flags);

    // Clean up if necessary
    if (metadata != nullptr) {
        // Assuming there's a function to free the allocated metadata
        // aom_img_metadata_free(metadata);
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

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
