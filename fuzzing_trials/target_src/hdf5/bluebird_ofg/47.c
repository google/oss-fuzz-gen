#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h> // Include the standard I/O library for mkstemp

int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    if (size < 2) {
        return 0; // Ensure there's enough data for the strings
    }

    // Create a temporary file to simulate file input
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        return 0; // Failed to create temporary file
    }

    // Close the file descriptor as we will use HDF5 functions to handle the file
    close(fd);

    // Create a new HDF5 file using the template filename
    hid_t file_id = H5Fcreate(tmpl, H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        unlink(tmpl);
        return 0; // Failed to create an HDF5 file
    }

    // Close the file to prepare for reopening
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function H5Fclose with H5Freset_page_buffering_stats
    H5Freset_page_buffering_stats(file_id);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

    // Reopen the file to get a valid file_id
    file_id = H5Fopen(tmpl, H5F_ACC_RDWR, H5P_DEFAULT);
    if (file_id < 0) {
        unlink(tmpl);
        return 0; // Failed to open the file
    }

    // Prepare parameters for H5Freopen_async
    unsigned int flags = (unsigned int)data[0]; // Use first byte as flags
    hid_t dxpl_id = (hid_t)data[1]; // Use second byte as dxpl_id
    hid_t es_id = H5P_DEFAULT; // Use a default event set ID

    // Call the function-under-test
    hid_t result = H5Freopen_async(file_id, es_id);

    // Close the file and clean up
    H5Fclose(file_id);
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

    LLVMFuzzerTestOneInput_47(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
