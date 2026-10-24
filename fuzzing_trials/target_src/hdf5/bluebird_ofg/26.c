#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"
#include <unistd.h>

int LLVMFuzzerTestOneInput_26(const uint8_t *data, size_t size) {
    // Create a temporary file to use as input for H5Fdelete
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    
    // Write the fuzz data to the temporary file
    if (write(fd, data, size) == -1) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    
    // Close the file descriptor
    close(fd);
    
    // Define a valid file access property list identifier
    hid_t fapl_id = H5Pcreate(H5P_FILE_ACCESS);
    if (fapl_id < 0) {
        unlink(tmpl);
        return 0;
    }

    // Call H5Fdelete with the temporary file path and file access property list
    herr_t status = H5Fdelete(tmpl, fapl_id);

    // Clean up
    H5Pclose(fapl_id);
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

    LLVMFuzzerTestOneInput_26(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
