#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_260(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract meaningful strings
    if (size < 4) {
        return 0;
    }

    // Create a temporary file to work with HDF5
    char filename[] = "fuzz_temp.h5";
    hid_t file_id = H5Fcreate(filename, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Extract two strings for object_name and attr_name from the data
    size_t half_size = size / 2;
    char *object_name = (char *)malloc(half_size + 1);
    char *attr_name = (char *)malloc(size - half_size + 1);

    if (object_name == NULL || attr_name == NULL) {
        H5Fclose(file_id);
        free(object_name);
        free(attr_name);
        return 0;
    }

    memcpy(object_name, data, half_size);
    object_name[half_size] = '\0';

    memcpy(attr_name, data + half_size, size - half_size);
    attr_name[size - half_size] = '\0';

    // Use a valid hid_t for lapl_id, using H5P_DEFAULT for simplicity
    hid_t lapl_id = H5P_DEFAULT;

    // Call the function-under-test
    H5Adelete_by_name(file_id, object_name, attr_name, lapl_id);

    // Clean up
    H5Fclose(file_id);
    free(object_name);
    free(attr_name);

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

    LLVMFuzzerTestOneInput_260(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
