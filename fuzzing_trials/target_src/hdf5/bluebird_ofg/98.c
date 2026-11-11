#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_98(const uint8_t *data, size_t size) {
    if (size < 10) {
        return 0;
    }

    // Use the first byte of data as a simple way to initialize hid_t variables
    hid_t dset_id = (hid_t)data[0];
    hid_t mem_type_id = (hid_t)data[1];
    hid_t mem_space_id = (hid_t)data[2];
    hid_t file_space_id = (hid_t)data[3];
    hid_t dxpl_id = (hid_t)data[4];

    // Allocate memory for the buffer and ensure it's not NULL
    void *buf = malloc(1);
    if (buf == NULL) {
        return 0;
    }

    // Use the first byte of data to initialize es_id
    hid_t es_id = (hid_t)data[5];

    // Call the function-under-test using the macro which automatically fills in app_file, app_func, and app_line
    herr_t result = H5Dread_async(dset_id, mem_type_id, mem_space_id, file_space_id, dxpl_id, buf, es_id);

    // Free allocated memory
    free(buf);

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

    LLVMFuzzerTestOneInput_98(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
