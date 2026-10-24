#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>
#include <string.h>

int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t loc_id = 1; // Example non-negative hid_t value
    const char *obj_name = "example_object";
    const char *attr_name = "example_attribute";
    hid_t type_id = 2; // Example non-negative hid_t value
    hid_t space_id = 3; // Example non-negative hid_t value
    hid_t acpl_id = 4; // Example non-negative hid_t value
    hid_t aapl_id = 5; // Example non-negative hid_t value
    hid_t lapl_id = 6; // Example non-negative hid_t value

    // Ensure the data is not empty
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test
    hid_t result = H5Acreate_by_name(loc_id, obj_name, attr_name, type_id, space_id, acpl_id, aapl_id, lapl_id);

    // Use the result to avoid unused variable warning
    (void)result;

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

    LLVMFuzzerTestOneInput_95(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
