#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract meaningful data
    if (size < 5) return 0;

    // Initialize HDF5 library
    H5open();

    // Extract parameters from the data
    hid_t loc_id = (hid_t)data[0];
    const char *name = (const char *)&data[1];  // Using the rest of the data as a string
    hid_t lcpl_id = (hid_t)data[2];
    hid_t gcpl_id = (hid_t)data[3];
    hid_t gapl_id = (hid_t)data[4];

    // Ensure the name is null-terminated
    char name_buffer[256];
    size_t name_length = size - 1 < 255 ? size - 1 : 255;
    for (size_t i = 0; i < name_length; i++) {
        name_buffer[i] = name[i];
    }
    name_buffer[name_length] = '\0';

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(loc_id, name_buffer, lcpl_id, gcpl_id, gapl_id);

    // Close the group if it was successfully created
    if (group_id >= 0) {
        H5Gclose(group_id);
    }

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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
