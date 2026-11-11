#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_185(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient for our needs
    if (size < 6 * sizeof(hid_t) + 1) {
        return 0;
    }

    // Extract hid_t values from the input data
    hid_t loc_id = *((hid_t *)data);
    hid_t type_id = *((hid_t *)(data + sizeof(hid_t)));
    hid_t space_id = *((hid_t *)(data + 2 * sizeof(hid_t)));
    hid_t acpl_id = *((hid_t *)(data + 3 * sizeof(hid_t)));
    hid_t aapl_id = *((hid_t *)(data + 4 * sizeof(hid_t)));
    hid_t lapl_id = *((hid_t *)(data + 5 * sizeof(hid_t)));

    // Extract a null-terminated string for the attribute name
    const char *attr_name = (const char *)(data + 6 * sizeof(hid_t));

    // Ensure the attribute name is null-terminated
    char *attr_name_copy = (char *)malloc(size - 6 * sizeof(hid_t) + 1);
    if (attr_name_copy == NULL) {
        return 0;
    }
    size_t attr_name_len = size - 6 * sizeof(hid_t);
    for (size_t i = 0; i < attr_name_len; ++i) {
        attr_name_copy[i] = attr_name[i];
    }
    attr_name_copy[attr_name_len] = '\0';

    // Call the function-under-test
    hid_t result = H5Acreate2(loc_id, attr_name_copy, type_id, space_id, acpl_id, aapl_id);

    // Clean up
    free(attr_name_copy);

    // Normally, you would check the result and handle errors, but for fuzzing, we just return
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

    LLVMFuzzerTestOneInput_185(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
