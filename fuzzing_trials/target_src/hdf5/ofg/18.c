#include <stdint.h>
#include <hdf5.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the strings and other parameters
    if (size < 4) {
        return 0;
    }

    // Extract parameters from the input data
    const char *old_name = (const char *)data;
    const char *new_name = (const char *)data + 1;
    hid_t loc_id = (hid_t)data[2];
    hid_t es_id = (hid_t)data[3];

    // Ensure null-termination of strings
    char old_name_buf[256];
    char new_name_buf[256];

    strncpy(old_name_buf, old_name, sizeof(old_name_buf) - 1);
    old_name_buf[sizeof(old_name_buf) - 1] = '\0';

    strncpy(new_name_buf, new_name, sizeof(new_name_buf) - 1);
    new_name_buf[sizeof(new_name_buf) - 1] = '\0';

    // Call the function under test
    H5Arename_async(loc_id, old_name_buf, new_name_buf, es_id);

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

    LLVMFuzzerTestOneInput_18(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
