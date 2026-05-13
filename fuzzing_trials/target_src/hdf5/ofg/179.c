#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_179(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for our needs
    if (size < 6) {
        return 0;
    }

    // Extract values from the input data
    hid_t loc_id = (hid_t)data[0];
    const char *attr_name = (const char *)&data[1];
    hid_t type_id = (hid_t)data[2];
    hid_t space_id = (hid_t)data[3];
    hid_t acpl_id = (hid_t)data[4];
    hid_t aapl_id = (hid_t)data[5];

    // Ensure attr_name is null-terminated
    char name_buffer[256];
    size_t name_length = size - 1 < 255 ? size - 1 : 255;
    for (size_t i = 0; i < name_length; ++i) {
        name_buffer[i] = attr_name[i];
    }
    name_buffer[name_length] = '\0';

    // Call the function-under-test
    hid_t result = H5Acreate2(loc_id, name_buffer, type_id, space_id, acpl_id, aapl_id);

    // Clean up and return
    if (result >= 0) {
        H5Aclose(result);
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

    LLVMFuzzerTestOneInput_179(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
