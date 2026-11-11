#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_6(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t loc_id = H5P_DEFAULT; // Default property list ID
    char group_name[256]; // Buffer for group name
    hid_t lcpl_id = H5P_DEFAULT; // Link creation property list ID
    hid_t gcpl_id = H5P_DEFAULT; // Group creation property list ID
    hid_t gapl_id = H5P_DEFAULT; // Group access property list ID

    // Ensure the data size is sufficient to create a valid group name
    if (size < 1) return 0;

    // Copy data to group_name, ensuring null-termination
    size_t copy_size = size < sizeof(group_name) ? size : sizeof(group_name) - 1;
    memcpy(group_name, data, copy_size);
    group_name[copy_size] = '\0';

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(loc_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Close the group if it was successfully created
    if (group_id >= 0) {
        H5Gclose(group_id);
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

    LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
