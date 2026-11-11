#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <string.h>
#include <unistd.h> // Include this for mkstemp() and unlink()

int LLVMFuzzerTestOneInput_147(const uint8_t *data, size_t size) {
    // Define variables
    hid_t loc_id = 1; // Assuming a valid non-zero ID for location
    hid_t child_id = 2; // Assuming a valid non-zero ID for child
    hid_t plist_id = 3; // Assuming a valid non-zero ID for property list

    // Create a temporary filename for the mount point
    char filename[] = "/tmp/fuzz_mountXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0; // Exit if unable to create a temporary file
    }
    close(fd);

    // Ensure the data is null-terminated for string operations
    char *mount_name = (char *)malloc(size + 1);
    if (mount_name == NULL) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(mount_name, data, size);
    mount_name[size] = '\0';

    // Call the function-under-test
    H5Fmount(loc_id, mount_name, child_id, plist_id);

    // Clean up
    free(mount_name);
    unlink(filename); // Remove the temporary file

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

    LLVMFuzzerTestOneInput_147(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
