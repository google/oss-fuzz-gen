#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    if (size < sizeof(hid_t) + sizeof(unsigned int) + sizeof(size_t)) {
        return 0; // Ensure there's enough data to extract parameters
    }

    // Extract parameters from the input data
    hid_t file_id = *((hid_t *)data);
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    unsigned int types = *((unsigned int *)data);
    data += sizeof(unsigned int);
    size -= sizeof(unsigned int);

    size_t max_objs = *((size_t *)data);
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Allocate memory for object IDs
    hid_t *obj_ids = (hid_t *)malloc(max_objs * sizeof(hid_t));
    if (obj_ids == NULL) {
        return 0; // Memory allocation failed
    }

    // Call the function-under-test
    ssize_t result = H5Fget_obj_ids(file_id, types, max_objs, obj_ids);

    // Clean up
    free(obj_ids);

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

    LLVMFuzzerTestOneInput_36(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
