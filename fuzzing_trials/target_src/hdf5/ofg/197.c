#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>  // Include for mkstemp and unlink
#include <fcntl.h>   // Include for open
#include <sys/types.h> // Include for types like ssize_t
#include <sys/stat.h>  // Include for mode constants
#include <hdf5.h>

int LLVMFuzzerTestOneInput_197(const uint8_t *data, size_t size) {
    // Create a temporary file to hold the fuzz data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }
    close(fd);

    // Set the flags and fapl_id for H5Fopen
    unsigned int flags = H5F_ACC_RDONLY;  // Open the file as read-only
    hid_t fapl_id = H5P_DEFAULT;          // Default file access property list

    // Call the function-under-test
    hid_t file_id = H5Fopen(tmpl, flags, fapl_id);

    // Close the file if it was successfully opened
    if (file_id >= 0) {
        H5Fclose(file_id);
    }

    // Remove the temporary file
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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_197(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
