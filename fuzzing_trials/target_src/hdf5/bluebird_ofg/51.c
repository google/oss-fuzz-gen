#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_51(const uint8_t *data, size_t size) {
    // Ensure that the data size is sufficient for creating a null-terminated string
    if (size < 1) return 0;

    // Create a null-terminated string from the input data
    char *attr_name = (char *)malloc(size + 1);
    if (attr_name == NULL) return 0;
    memcpy(attr_name, data, size);
    attr_name[size] = '\0';

    // Initialize a valid hid_t object for testing
    hid_t file_id = H5Fcreate("testfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        free(attr_name);
        return 0;
    }

    // Call the function-under-test
    hid_t attribute_id = H5Aopen_name(file_id, attr_name);

    // Clean up resources
    if (attribute_id >= 0) {
        H5Aclose(attribute_id);
    }
    H5Fclose(file_id);
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
