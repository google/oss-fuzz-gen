#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_35(const uint8_t *data, size_t size) {
    // Variables for the function parameters
    hid_t file_id;
    unsigned int types;
    size_t max_objs;
    hid_t *obj_id_list;

    // Initialize the parameters with non-NULL values
    // Assuming the data is large enough to extract these values
    if (size < sizeof(hid_t) + sizeof(unsigned int) + sizeof(size_t)) {
        return 0;
    }

    // Extracting values from the input data
    file_id = *(hid_t *)data;
    types = *(unsigned int *)(data + sizeof(hid_t));
    max_objs = *(size_t *)(data + sizeof(hid_t) + sizeof(unsigned int));

    // Allocate memory for the object ID list
    obj_id_list = (hid_t *)malloc(max_objs * sizeof(hid_t));
    if (obj_id_list == NULL) {
        return 0;
    }

    // Call the function-under-test
    ssize_t result = H5Fget_obj_ids(file_id, types, max_objs, obj_id_list);

    // Free allocated memory
    free(obj_id_list);

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

    LLVMFuzzerTestOneInput_35(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
