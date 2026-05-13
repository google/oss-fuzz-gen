#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"
#include <unistd.h>  // For mkstemp
#include <stdio.h>   // For perror
#include <fcntl.h>   // For open
#include <string.h>  // For memset

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our needs
    if (size < 4) {
        return 0;
    }

    // Create temporary file names for the parameters
    char file_name[] = "/tmp/h5fuzzfileXXXXXX";
    int fd = mkstemp(file_name);
    if (fd == -1) {
        perror("mkstemp");
        return 0;
    }
    close(fd);

    // Extract values from the data for the parameters
    unsigned int flags = data[0];
    hid_t object_id = (hid_t)data[1];
    H5F_scope_t scope = (H5F_scope_t)data[2];
    hid_t es_id = (hid_t)data[3];

    // Open the file to ensure object_id is valid
    object_id = H5Fopen(file_name, flags, H5P_DEFAULT);
    if (object_id < 0) {
        unlink(file_name);
        return 0;
    }

    // Call the function-under-test
    herr_t result = H5Fflush_async(object_id, scope, es_id);

    // Close the file
    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function H5Fclose with H5Fstart_swmr_write
    H5Fstart_swmr_write(object_id);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR

    // Clean up temporary file
    unlink(file_name);

    // Return 0 to indicate success
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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
