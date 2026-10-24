#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    // Initialize the parameters for H5Gget_objname_by_idx
    hid_t group_id = H5I_INVALID_HID;  // Invalid ID for demonstration
    hsize_t idx = 0;
    char name_buf[256];
    size_t buf_size = sizeof(name_buf);

    // Ensure data is large enough to extract meaningful values
    if (size >= sizeof(hid_t) + sizeof(hsize_t)) {
        // Extract values from the input data
        memcpy(&group_id, data, sizeof(hid_t));
        memcpy(&idx, data + sizeof(hid_t), sizeof(hsize_t));
    }

    // Call the function-under-test
    ssize_t name_len = H5Gget_objname_by_idx(group_id, idx, name_buf, buf_size);

    // Optionally, you can use name_len or name_buf for further processing

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

    LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
