#include <stdint.h>
#include <hdf5.h>

herr_t dummy_operator_145(hid_t location_id, const char *attr_name, const H5A_info_t *ainfo, void *op_data) {
    // Dummy operator function for iteration
    return 0;
}

int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    hid_t loc_id;
    unsigned int idx;
    H5A_operator1_t op;
    void *op_data;

    if (size < sizeof(hid_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Initialize loc_id and idx from the input data
    loc_id = *(hid_t *)data;
    idx = *(unsigned int *)(data + sizeof(hid_t));

    // Set the operator function and op_data
    op = dummy_operator_145;
    op_data = (void *)(data + sizeof(hid_t) + sizeof(unsigned int));

    // Call the function-under-test
    H5Aiterate1(loc_id, &idx, op, op_data);

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

    LLVMFuzzerTestOneInput_145(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
