#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 4) return 0;

    // Initialize variables
    hid_t loc_id = (hid_t)data[0]; // Use the first byte as loc_id
    const char *name = "fuzz_group"; // Use a fixed name for the group
    hid_t lcpl_id = (hid_t)data[1]; // Use the second byte as lcpl_id
    hid_t gcpl_id = (hid_t)data[2]; // Use the third byte as gcpl_id
    hid_t gapl_id = (hid_t)data[3]; // Use the fourth byte as gapl_id

    // Call the function-under-test
    hid_t group_id = H5Gcreate2(loc_id, name, lcpl_id, gcpl_id, gapl_id);

    // Close the group if it was created successfully
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
