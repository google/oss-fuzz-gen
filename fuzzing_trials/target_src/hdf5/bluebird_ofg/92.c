#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_92(const uint8_t *data, size_t size) {
    if (size < 6) {
        return 0; // Ensure there's enough data for all parameters
    }

    // Prepare parameters for H5Arename_async
    hid_t loc_id = 1; // Example non-negative integer
    const char *old_name = "old_attribute_name";
    const char *new_name = "new_attribute_name";
    hid_t es_id = 2; // Example non-negative integer

    // Call the function-under-test
    H5Arename_async(loc_id, old_name, new_name, es_id);

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

    LLVMFuzzerTestOneInput_92(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
