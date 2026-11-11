#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_15(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzing data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Define the flags and file access property list
    unsigned int flags = H5F_ACC_RDONLY; // Read-only access
    hid_t fapl_id = H5P_DEFAULT; // Default file access property list

    // Call the function-under-test
    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of H5Fopen
    hid_t file_id = H5Fopen(tmpl, 1, fapl_id);
    // End mutation: Producer.REPLACE_ARG_MUTATOR

    // If the file was opened successfully, close it
    if (file_id >= 0) {
        // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function H5Fclose with H5Fformat_convert
        H5Fformat_convert(file_id);
        // End mutation: Producer.REPLACE_FUNC_MUTATOR
    }

    // Clean up the temporary file

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from H5Fopen to H5Fmount using the plateau pool

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from H5Fopen to H5Dcreate2 using the plateau pool
    hsize_t dims[1] = {size};
    hid_t space_id = H5Screate_simple(1, dims, NULL);
    hid_t ret_H5Dcreate2_kdnha = H5Dcreate2(file_id, "dataset", H5T_NATIVE_UINT8, space_id, H5P_DEFAULT, H5P_DEFAULT, H5P_DEFAULT);
    // End mutation: Producer.SPLICE_MUTATOR
    

    // Begin mutation: Producer.SPLICE_MUTATOR - Spliced data flow from H5Dcreate2 to H5Fget_info2 using the plateau pool
    H5F_info2_t file_info;
    herr_t ret_H5Fget_info2_rpugo = H5Fget_info2(ret_H5Dcreate2_kdnha, &file_info);
    // End mutation: Producer.SPLICE_MUTATOR
    
    hid_t plist_id = H5P_DEFAULT;
    herr_t ret_H5Fmount_oxzis = H5Fmount(file_id, "/mount_point", file_id, plist_id);
    // End mutation: Producer.SPLICE_MUTATOR
    
    unlink(tmpl);

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
