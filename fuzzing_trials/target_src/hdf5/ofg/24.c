#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for creating a filename
    if (size < 5) return 0;

    // Create a temporary file name
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0; // If unable to create a temp file, exit
    }
    close(fd); // Close the file descriptor as we only need the filename

    // Use the data to set flags and property lists
    unsigned int flags = (unsigned int)data[0];
    hid_t fcpl_id = (hid_t)data[1];
    hid_t fapl_id = (hid_t)data[2];

    // Call the function-under-test
    hid_t file_id = H5Fcreate(tmpl, flags, fcpl_id, fapl_id);

    // If the file was successfully created, close it
    if (file_id >= 0) {
        H5Fclose(file_id);
    }

    // Clean up the temporary file
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

    LLVMFuzzerTestOneInput_24(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
