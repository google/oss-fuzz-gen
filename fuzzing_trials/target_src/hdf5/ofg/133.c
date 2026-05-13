#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract hid_t and hsize_t
    if (size < sizeof(hid_t) + sizeof(hsize_t)) {
        return 0;
    }

    // Extract hid_t from the input data
    hid_t file_id = *((hid_t *)data);

    // Extract hsize_t from the input data
    hsize_t idx = *((hsize_t *)(data + sizeof(hid_t)));

    // Call the function-under-test
    H5G_obj_t obj_type = H5Gget_objtype_by_idx(file_id, idx);

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

    LLVMFuzzerTestOneInput_133(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
