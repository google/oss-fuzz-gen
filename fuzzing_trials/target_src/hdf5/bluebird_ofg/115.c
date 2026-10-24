#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    hid_t dataset_id;
    haddr_t offset;

    // Ensure the input size is sufficient to create a valid HDF5 identifier
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Initialize the HDF5 library
    H5open();

    // Use the first part of the data to create a hid_t object
    dataset_id = *((hid_t*)data);

    // Call the function-under-test
    offset = H5Dget_offset(dataset_id);

    // Close the HDF5 library
    H5close();

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

    LLVMFuzzerTestOneInput_115(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
