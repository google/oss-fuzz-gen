#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t dataset_id = H5I_INVALID_HID; // Invalid ID for testing
    hsize_t chunk_offset[2] = {0, 0};   // Initialize with zero offsets
    hsize_t storage_size = 0;           // Variable to store the result

    // Ensure the input size is sufficient for our needs
    if (size < sizeof(hid_t) + 2 * sizeof(hsize_t)) {
        return 0;
    }

    // Extract dataset_id and chunk_offset from the input data
    dataset_id = *((hid_t *)data);
    chunk_offset[0] = *((hsize_t *)(data + sizeof(hid_t)));
    chunk_offset[1] = *((hsize_t *)(data + sizeof(hid_t) + sizeof(hsize_t)));

    // Call the function-under-test
    herr_t result = H5Dget_chunk_storage_size(dataset_id, chunk_offset, &storage_size);

    // Use the result and storage_size for further testing or logging if needed

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

    LLVMFuzzerTestOneInput_53(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
