#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Ensure there's enough data for at least a minimal string and hid_t values
    if (size < 5) {
        return 0;
    }

    // Extract hid_t values from the data
    hid_t loc_id = (hid_t)data[0];
    hid_t lcpl_id = (hid_t)data[1];
    hid_t gcpl_id = (hid_t)data[2];
    hid_t gapl_id = (hid_t)data[3];

    // Create a null-terminated string from the remaining data
    size_t name_length = size - 4;
    char *name = (char *)malloc(name_length + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 4, name_length);
    name[name_length] = '\0';

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(loc_id, name, lcpl_id, gcpl_id, gapl_id);

    // Clean up
    free(name);

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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
