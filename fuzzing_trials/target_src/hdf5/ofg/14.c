#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_14(const uint8_t *data, size_t size) {
    // Ensure there's enough data to work with
    if (size < 2) {
        return 0;
    }

    // Use the first part of the data as a fake hid_t
    hid_t loc_id = (hid_t)data[0];

    // Use the rest of the data as a name, ensuring it's null-terminated
    size_t name_len = size - 1;
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, &data[1], name_len);
    name[name_len] = '\0';

    // Call the function under test
    hid_t attribute_id = H5Aopen_name(loc_id, name);

    // Clean up
    free(name);

    // Close the attribute if it was successfully opened
    if (attribute_id >= 0) {
        H5Aclose(attribute_id);
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

    LLVMFuzzerTestOneInput_14(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
