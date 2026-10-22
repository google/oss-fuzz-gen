#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_36(const uint8_t *data, size_t size) {
    // Ensure there's enough data for a string and at least 6 hid_t values
    if (size < sizeof(hid_t) * 6 + 1) {
        return 0;
    }

    // Extract the first 6 hid_t values from the data
    hid_t loc_id = *((hid_t *)data);
    hid_t type_id = *((hid_t *)(data + sizeof(hid_t)));
    hid_t space_id = *((hid_t *)(data + 2 * sizeof(hid_t)));
    hid_t lcpl_id = *((hid_t *)(data + 3 * sizeof(hid_t)));
    hid_t dcpl_id = *((hid_t *)(data + 4 * sizeof(hid_t)));
    hid_t dapl_id = *((hid_t *)(data + 5 * sizeof(hid_t)));

    // Use the remaining data as a null-terminated string for the dataset name
    const char *dataset_name = (const char *)(data + 6 * sizeof(hid_t));
    size_t name_length = size - 6 * sizeof(hid_t);

    // Ensure the dataset name is null-terminated
    char *name = (char *)malloc(name_length + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, dataset_name, name_length);
    name[name_length] = '\0';

    // Call the function-under-test
    hid_t dataset_id = H5Dcreate2(loc_id, name, type_id, space_id, lcpl_id, dcpl_id, dapl_id);

    // Clean up
    free(name);

    // If the dataset was created successfully, close it
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

    LLVMFuzzerTestOneInput_36(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
