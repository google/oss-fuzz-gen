#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract meaningful values for parameters
    if (size < 6 * sizeof(hid_t) + 1) {
        return 0;
    }

    // Extract parameters from the input data
    size_t offset = 0;
    hid_t loc_id = *((hid_t *)(data + offset));
    offset += sizeof(hid_t);
    const char *name = (const char *)(data + offset);
    offset += 1; // Move offset by 1 to ensure name is not NULL
    hid_t type_id = *((hid_t *)(data + offset));
    offset += sizeof(hid_t);
    hid_t space_id = *((hid_t *)(data + offset));
    offset += sizeof(hid_t);
    hid_t lcpl_id = *((hid_t *)(data + offset));
    offset += sizeof(hid_t);
    hid_t dcpl_id = *((hid_t *)(data + offset));
    offset += sizeof(hid_t);
    hid_t dapl_id = *((hid_t *)(data + offset));

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Close the dataset if it was created successfully
    if (dataset_id >= 0) {
        H5Dclose(dataset_id);
    }

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

    LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
