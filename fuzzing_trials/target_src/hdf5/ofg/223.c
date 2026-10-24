#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_223(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the string and ids
    if (size < 20) return 0;

    // Extract a string from the input data
    const char *name = (const char *)data;

    // Extract hid_t values from the input data
    hid_t loc_id = (hid_t)data[0];
    hid_t type_id = (hid_t)data[1];
    hid_t space_id = (hid_t)data[2];
    hid_t lcpl_id = (hid_t)data[3];
    hid_t dcpl_id = (hid_t)data[4];
    hid_t dapl_id = (hid_t)data[5];

    // Call the function under test
    hid_t dataset_id = H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Close the dataset if it was successfully created
    if (dataset_id >= 0) {
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_223(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
