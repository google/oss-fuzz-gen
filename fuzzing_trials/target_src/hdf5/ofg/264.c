#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_264(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract parameters
    if (size < sizeof(hid_t) + sizeof(hsize_t) + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from the input data
    hid_t loc_id = *((hid_t *)data);
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    hsize_t idx = *((hsize_t *)data);
    data += sizeof(hsize_t);
    size -= sizeof(hsize_t);

    size_t buf_size = *((size_t *)data);
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Allocate a buffer for the object name
    char *name_buf = (char *)malloc(buf_size);
    if (name_buf == NULL) {
        return 0;
    }

    // Call the function-under-test
    ssize_t result = H5Gget_objname_by_idx(loc_id, idx, name_buf, buf_size);

    // Clean up
    free(name_buf);

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

    LLVMFuzzerTestOneInput_264(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
