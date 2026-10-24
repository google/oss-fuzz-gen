#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t dataset_id = H5I_INVALID_HID; // Assuming invalid ID for fuzzing
    hsize_t dims[1] = {1}; // Minimal dimension for testing
    hsize_t storage_size = 0;

    // Ensure data size is sufficient for fuzzing
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Use the data to create a valid hid_t for fuzzing
    dataset_id = *((hid_t *)data);

    // Call the function-under-test
    herr_t result = H5Dget_chunk_storage_size(dataset_id, dims, &storage_size);

    // Return 0 to indicate the fuzzer should continue
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

    LLVMFuzzerTestOneInput_122(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
