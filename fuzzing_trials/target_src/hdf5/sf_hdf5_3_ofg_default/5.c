#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include the string.h library for memcpy
#include <hdf5.h>

int LLVMFuzzerTestOneInput_5(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the string and ids
    if (size < 3 * sizeof(hid_t) + 1) {
        return 0;
    }

    // Extract the hid_t values from the data
    hid_t loc_id = *((hid_t *)data);
    hid_t lcpl_id = *((hid_t *)(data + sizeof(hid_t)));
    hid_t gcpl_id = *((hid_t *)(data + 2 * sizeof(hid_t)));
    hid_t gapl_id = *((hid_t *)(data + 3 * sizeof(hid_t)));

    // Use the remaining data for the group name, ensuring it's null-terminated
    size_t name_length = size - 3 * sizeof(hid_t);
    char *group_name = (char *)malloc(name_length + 1);
    if (group_name == NULL) {
        return 0;
    }
    memcpy(group_name, data + 3 * sizeof(hid_t), name_length);
    group_name[name_length] = '\0';

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(loc_id, group_name, lcpl_id, gcpl_id, gapl_id);

    // Cleanup
    free(group_name);

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

    LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
