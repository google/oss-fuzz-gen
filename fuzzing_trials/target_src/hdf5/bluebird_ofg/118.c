#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_118(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for extracting the necessary parameters
    if (size < sizeof(hid_t) + sizeof(bool)) {
        return 0;
    }

    // Extract hid_t and bool from the data
    hid_t file_id = *((hid_t *)data);
    bool no_attrs_hint = *((bool *)(data + sizeof(hid_t)));

    // Call the function-under-test
    H5Fset_dset_no_attrs_hint(file_id, no_attrs_hint);

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

    LLVMFuzzerTestOneInput_118(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
