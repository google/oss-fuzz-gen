#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Initialize the HDF5 library
    H5open();

    // Ensure there's enough data to work with
    if (size < 2) {
        return 0;
    }

    // Use the first byte of data to create a simple hid_t identifier
    // Note: In real-world scenarios, hid_t identifiers are obtained from HDF5 functions
    hid_t loc_id = (hid_t)data[0];

    // Use the second byte of data to create another hid_t identifier
    hid_t aapl_id = (hid_t)data[1];

    // Use the rest of the data as the attribute name, ensuring it's null-terminated
    char attr_name[256];
    size_t name_len = size - 2 < 255 ? size - 2 : 255;
    for (size_t i = 0; i < name_len; i++) {
        attr_name[i] = (char)data[i + 2];
    }
    attr_name[name_len] = '\0';

    // Call the function-under-test
    hid_t attr_id = H5Aopen(loc_id, attr_name, aapl_id);

    // Close the attribute if it was successfully opened
    if (attr_id >= 0) {
        H5Aclose(attr_id);
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_30(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
