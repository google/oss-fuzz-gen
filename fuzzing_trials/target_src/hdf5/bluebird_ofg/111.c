#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>
#include "hdf5.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_111(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0; // Ensure there is enough data for the parameters
    }

    // Initialize variables for function parameters
    hid_t obj_id = H5I_INVALID_HID; // Use an invalid ID initially
    const char *attr_name = "dummy_attr_name";
    _Bool exists = false;
    hid_t es_id = H5P_DEFAULT;

    // Call the function-under-test
    herr_t result = H5Aexists_async(obj_id, attr_name, &exists, es_id);

    // Use the result and exists variable to prevent unused variable warnings
    if (result < 0) {
        // Handle error
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

    LLVMFuzzerTestOneInput_111(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
