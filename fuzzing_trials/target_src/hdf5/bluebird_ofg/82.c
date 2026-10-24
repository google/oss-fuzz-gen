#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
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
    hid_t file_id = H5Fopen(tmpl, flags, fapl_id);

    // If the file was opened successfully, close it
    if (file_id >= 0) {
        H5Fclose(file_id);
    }

    // Clean up the temporary file

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from H5Fopen to H5Dwrite_chunk
    hid_t ret_H5Dget_access_plist_idyhx = H5Dget_access_plist(file_id);
    hsize_t ret_H5Aget_storage_size_npzjt = H5Aget_storage_size(0);
    char lzxqaljf[1024] = "xmbgw";
    herr_t ret_H5Dwrite_chunk_qegoc = H5Dwrite_chunk(ret_H5Dget_access_plist_idyhx, file_id, size, &ret_H5Aget_storage_size_npzjt, 1, lzxqaljf);
    // End mutation: Producer.APPEND_MUTATOR
    
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

    LLVMFuzzerTestOneInput_82(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
