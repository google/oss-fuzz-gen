#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "hdf5.h"

// Corrected the C++ linkage specification for C code
int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    // Initialize the HDF5 library
    H5open();

    // Create a temporary file to use with HDF5
    char tmpl[] = "/tmp/hdf5fileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Create an HDF5 file
    hid_t file_id = H5Fcreate(tmpl, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0;
    }

    // Create a group in the file

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from H5Fcreate to H5Fget_intent using the plateau pool
    unsigned int intent = 0;
    herr_t ret_H5Fget_intent_phuzs = H5Fget_intent(file_id, &intent);
    // End mutation: Producer.SPLICE_MUTATOR
    
    hid_t group_id = H5Gcreate2(file_id, "/test_group", H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    if (group_id < 0) {
        H5Fclose(file_id);
        return 0;
    }

    // Ensure the data is null-terminated before using it as a string
    char *obj_name = (char *)malloc(size + 1);
    if (obj_name == NULL) {
        H5Gclose(group_id);
        H5Fclose(file_id);
        return 0;
    }
    memcpy(obj_name, data, size);
    obj_name[size] = '\0';

    // Prepare the H5G_stat_t structure
    H5G_stat_t statbuf;

    // Call the function-under-test
    herr_t status = H5Gget_objinfo(group_id, obj_name, true, &statbuf);

    // Clean up
    free(obj_name);
    H5Gclose(group_id);
    H5Fclose(file_id);
    remove(tmpl);

    // Close the HDF5 library
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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
