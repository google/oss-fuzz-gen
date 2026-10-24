#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Ensure we have enough data to create a valid hid_t
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Create a hid_t from the input data
    hid_t dataset_id = *((hid_t*)data);

    // Call the function-under-test
    // We should ensure that dataset_id is a valid HDF5 identifier before closing
    if (H5Iis_valid(dataset_id)) {
        H5Dclose(dataset_id);
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

    LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
