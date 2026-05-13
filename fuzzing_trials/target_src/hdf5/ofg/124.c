#include <stdint.h>
#include <hdf5.h>

// Define a simple operator function to be used with H5Diterate
herr_t my_operator_124(void *elem, hid_t type_id, hsize_t ndim, hssize_t *point, void *operator_data) {
    // For fuzzing purposes, we can simply return 0
    return 0;
}

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for H5Diterate
    void *buf = (void *)data; // Use the input data as the buffer
    hid_t type_id = H5T_NATIVE_INT; // Use a basic HDF5 datatype
    hid_t space_id = H5Screate_simple(1, &size, NULL); // Create a simple dataspace
    H5D_operator_t op = my_operator_124; // Use the defined operator function
    void *operator_data = NULL; // No additional operator data

    // Call the function-under-test
    herr_t result = H5Diterate(buf, type_id, space_id, op, operator_data);

    // Clean up the created dataspace
    H5Sclose(space_id);

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

    LLVMFuzzerTestOneInput_124(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
