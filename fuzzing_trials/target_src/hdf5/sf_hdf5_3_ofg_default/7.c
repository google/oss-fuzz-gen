#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_7(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t loc_id = 1; // Assuming a valid location ID
    char group_name[256]; // Buffer for the group name
    hid_t lcpl_id = H5P_DEFAULT; // Link creation property list
    hid_t gcpl_id = H5P_DEFAULT; // Group creation property list
    hid_t gapl_id = H5P_DEFAULT; // Group access property list

    // Ensure the data size is within limits for group_name
    if (size > 0 && size < sizeof(group_name)) {
        // Copy data into group_name and null-terminate
        memcpy(group_name, data, size);
        group_name[size] = '\0';

        // Call the function under test
        hid_t group_id = H5Gcreate2(loc_id, group_name, lcpl_id, gcpl_id, gapl_id);

        // If the group was created successfully, close it
        if (group_id >= 0) {
            H5Gclose(group_id);
        }
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

    LLVMFuzzerTestOneInput_7(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
