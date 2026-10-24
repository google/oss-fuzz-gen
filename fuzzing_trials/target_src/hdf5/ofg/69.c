#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t dset_id = 1;  // Placeholder, should be a valid dataset identifier
    hid_t dxpl_id = 1;  // Placeholder, should be a valid data transfer property list identifier
    uint32_t filters = 0;  // No filters applied

    // Ensure that size is sufficient for at least one hsize_t
    if (size < sizeof(hsize_t)) {
        return 0;
    }

    // Use the first part of data as the offset
    const hsize_t *offset = (const hsize_t *)data;

    // Calculate remaining size for chunk data
    size_t chunk_size = size - sizeof(hsize_t);
    const void *chunk_data = (const void *)(data + sizeof(hsize_t));

    // Call the function-under-test
    herr_t result = H5Dwrite_chunk(dset_id, dxpl_id, filters, offset, chunk_size, chunk_data);

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_69(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
