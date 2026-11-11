#include <sys/stat.h>
#include "hdf5.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

// Include the necessary header for mkstemp
#include <stdlib.h>

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use as the HDF5 file
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Write the input data to the temporary file
    FILE *file = fopen(tmpl, "wb");
    if (!file) {
        unlink(tmpl);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Prepare parameters for H5Fopen_async
    const char *filename = tmpl;
    unsigned int flags = H5F_ACC_RDONLY; // Open file in read-only mode
    hid_t access_plist = H5P_DEFAULT;
    hid_t es_id = H5ES_NONE; // Event stack ID

    // Call the function-under-test
    hid_t file_id = H5Fopen_async(filename, flags, access_plist, es_id);

    // Cleanup
    if (file_id >= 0) {
        H5Fclose(file_id);
    }
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

    LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
