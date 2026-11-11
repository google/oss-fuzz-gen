#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t file_id;
    unsigned int types;

    // Ensure there is enough data to extract parameters
    if (size < sizeof(hid_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Extract parameters from data
    file_id = *(hid_t *)data;
    types = *(unsigned int *)(data + sizeof(hid_t));

    // Call the function-under-test
    ssize_t result = H5Fget_obj_count(file_id, types);

    // Use the result to prevent compiler optimizations
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_60(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
