#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract necessary parameters
    if (size < 10) {
        return 0;
    }

    // Extract parameters from the data
    hid_t link_loc_id = (hid_t)(data[0]);
    const char *link_name = (const char *)(data + 1);
    H5L_type_t link_type = (H5L_type_t)(data[2]);
    hid_t obj_loc_id = (hid_t)(data[3]);
    const char *obj_name = (const char *)(data + 4);

    // Ensure the strings are null-terminated
    char link_name_buffer[4];
    char obj_name_buffer[6];
    memcpy(link_name_buffer, link_name, 3);
    link_name_buffer[3] = '\0';
    memcpy(obj_name_buffer, obj_name, 5);
    obj_name_buffer[5] = '\0';

    // Call the function-under-test
    herr_t result = H5Glink2(link_loc_id, link_name_buffer, link_type, obj_loc_id, obj_name_buffer);

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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
