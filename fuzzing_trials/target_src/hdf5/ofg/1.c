#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // Define and initialize variables for H5Dwrite_multi
    size_t count = 1; // Number of datasets
    hid_t dset_id = H5I_INVALID_HID; // Dataset identifier
    hid_t mem_type_id = H5T_NATIVE_INT; // Memory datatype identifier
    hid_t mem_space_id = H5S_ALL; // Memory dataspace identifier
    hid_t file_space_id = H5S_ALL; // File dataspace identifier
    hid_t plist_id = H5P_DEFAULT; // Property list identifier
    const void *buf = data; // Buffer with data to write

    // Allocate memory for the array of identifiers
    hid_t *dset_ids = (hid_t *)malloc(count * sizeof(hid_t));
    if (dset_ids == NULL) {
        return 0; // Memory allocation failed
    }

    // Initialize the dataset identifiers
    for (size_t i = 0; i < count; i++) {
        dset_ids[i] = dset_id;
    }

    // Call the function-under-test
    herr_t status = H5Dwrite_multi(count, dset_ids, &mem_type_id, &mem_space_id, &file_space_id, plist_id, &buf);

    // Free allocated memory
    free(dset_ids);

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

    LLVMFuzzerTestOneInput_1(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
