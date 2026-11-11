#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_95(const uint8_t *data, size_t size) {
    // Ensure the data size is large enough to extract required parameters
    if (size < 10) {
        return 0;
    }

    // Extract parameters from the data
    hid_t dset_id = (hid_t)data[0];
    hid_t mem_type_id = (hid_t)data[1];
    hid_t mem_space_id = (hid_t)data[2];
    hid_t file_space_id = (hid_t)data[3];
    hid_t dxpl_id = (hid_t)data[4];
    const void *buf = (const void *)(data + 5);
    hid_t es_id = (hid_t)data[6];

    // Call the function-under-test
    herr_t result = H5Dwrite_async(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, buf, es_id);

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

    LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
