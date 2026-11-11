#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_166(const uint8_t *data, size_t size) {
    // Define and initialize variables
    hid_t loc_id = 1; // Assuming a valid hid_t value for location ID
    const char *obj_name = "test_object"; // Example object name
    H5_index_t idx_type = H5_INDEX_NAME; // Example index type
    H5_iter_order_t order = H5_ITER_INC; // Example iteration order
    hsize_t n = 0; // Example index position
    char name[256]; // Buffer to store the attribute name
    size_t buf_size = sizeof(name); // Size of the buffer
    hid_t lapl_id = H5P_DEFAULT; // Link access property list

    // Ensure that data is not NULL and size is sufficient
    if (data == NULL || size < 1) {
        return 0;
    }

    // Call the function-under-test
    ssize_t result = H5Aget_name_by_idx(loc_id, obj_name, idx_type, order, n, name, buf_size, lapl_id);

    // Use the result to prevent compiler optimizations from removing the call
    if (result < 0) {
        // Handle error if needed
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_166(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
