#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Ensure there's enough data to create a valid string and IDs
    if (size < 11) {
        return 0;
    }

    // Create a null-terminated string from the data
    char name[6];
    memcpy(name, data, 5);
    name[5] = '\0';

    // Extract hid_t values from the data
    hid_t loc_id = (hid_t)data[5];
    hid_t type_id = (hid_t)data[6];
    hid_t space_id = (hid_t)data[7];
    hid_t lcpl_id = (hid_t)data[8];
    hid_t dcpl_id = (hid_t)data[9];
    hid_t dapl_id = (hid_t)data[10];

    // Call the function-under-test
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_25(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
