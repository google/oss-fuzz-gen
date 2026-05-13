#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_234(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t loc_id = 1; // Assuming a valid non-zero hid_t for location identifier
    hid_t lapl_id = 1; // Assuming a valid non-zero hid_t for link access property list

    // Ensure that the size is sufficient to extract strings
    if (size < 3) {
        return 0;
    }

    // Extract strings from the input data
    const char *obj_name = (const char *)data;
    const char *old_attr_name = (const char *)(data + 1);
    const char *new_attr_name = (const char *)(data + 2);

    // Call the function-under-test
    H5Arename_by_name(loc_id, obj_name, old_attr_name, new_attr_name, lapl_id);

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

    LLVMFuzzerTestOneInput_234(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
