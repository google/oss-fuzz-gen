#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    // Initialize HDF5 library
    H5open();

    // Create a memory buffer to hold the data for the fuzzing input
    char *object_name = (char *)malloc(size + 1);
    char *attr_name = (char *)malloc(size + 1);

    // Ensure the memory allocation was successful
    if (object_name == NULL || attr_name == NULL) {
        free(object_name);
        free(attr_name);
        return 0;
    }

    // Copy data to the object_name and attr_name, ensuring they are null-terminated
    memcpy(object_name, data, size);
    object_name[size] = '\0';
    memcpy(attr_name, data, size);
    attr_name[size] = '\0';

    // Use a valid hid_t identifier for the location and lapl_id
    hid_t loc_id = H5P_DEFAULT; // Default property list ID
    hid_t lapl_id = H5P_DEFAULT; // Default link access property list ID

    // Call the function-under-test
    htri_t result = H5Aexists_by_name(loc_id, object_name, attr_name, lapl_id);

    // Clean up
    free(object_name);
    free(attr_name);

    // Close HDF5 library
    H5close();

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

    LLVMFuzzerTestOneInput_124(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
