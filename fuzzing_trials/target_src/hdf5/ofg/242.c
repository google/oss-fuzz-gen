#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_242(const uint8_t *data, size_t size) {
    // Define the number of datasets
    size_t num_datasets = 1; // You can adjust this number for more datasets

    // Allocate memory for the dataset identifiers
    hid_t *dset_ids = (hid_t *)malloc(num_datasets * sizeof(hid_t));
    hid_t *mem_types = (hid_t *)malloc(num_datasets * sizeof(hid_t));
    hid_t *mem_spaces = (hid_t *)malloc(num_datasets * sizeof(hid_t));
    hid_t *file_spaces = (hid_t *)malloc(num_datasets * sizeof(hid_t));

    // Initialize dataset identifiers with dummy values
    for (size_t i = 0; i < num_datasets; i++) {
        dset_ids[i] = H5I_INVALID_HID;
        mem_types[i] = H5T_NATIVE_INT;
        mem_spaces[i] = H5S_ALL;
        file_spaces[i] = H5S_ALL;
    }

    // Define a dummy property list
    hid_t dxpl_id = H5P_DEFAULT;

    // Allocate memory for the data buffers
    void **bufs = (void **)malloc(num_datasets * sizeof(void *));
    for (size_t i = 0; i < num_datasets; i++) {
        bufs[i] = malloc(size);
        if (bufs[i] != NULL) {
            memcpy(bufs[i], data, size);
        }
    }

    // Call the function-under-test
    herr_t result = H5Dread_multi(num_datasets, dset_ids, mem_types, mem_spaces, file_spaces, dxpl_id, bufs);

    // Free allocated memory
    for (size_t i = 0; i < num_datasets; i++) {
        free(bufs[i]);
    }
    free(bufs);
    free(dset_ids);
    free(mem_types);
    free(mem_spaces);
    free(file_spaces);

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

    LLVMFuzzerTestOneInput_242(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
