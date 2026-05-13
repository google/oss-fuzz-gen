#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    hid_t dset_id = 0; // Dummy dataset ID
    hid_t dxpl_id = 0; // Dummy data transfer property list ID
    uint32_t filters = 0; // No filters applied

    hsize_t offset[1] = {0}; // Single dimension offset
    if (size > 0) {
        offset[0] = (hsize_t)data[0]; // Use first byte of data as offset
    }

    size_t chunk_size = size; // Use the full size of data as chunk size

    // Call the function-under-test
    herr_t result = H5Dwrite_chunk(dset_id, dxpl_id, filters, offset, chunk_size, (const void *)data);

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

    LLVMFuzzerTestOneInput_68(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
