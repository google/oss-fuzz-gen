#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_226(const uint8_t *data, size_t size) {
    hid_t file_id;
    void *buffer = NULL;
    ssize_t result;

    // Create a temporary file to work with
    file_id = H5Fcreate("tempfile.h5", H5F_ACC_TRUNC, H5P_DEFAULT, H5P_DEFAULT);
    if (file_id < 0) {
        return 0; // Unable to create file, exit
    }

    // Allocate a buffer if size is greater than 0
    if (size > 0) {
        buffer = malloc(size);
        if (buffer == NULL) {
            H5Fclose(file_id);
            return 0; // Unable to allocate memory, exit
        }
        // Copy the data into the buffer
        memcpy(buffer, data, size);
    }

    // Call the function under test
    result = H5Fget_file_image(file_id, buffer, size);

    // Clean up
    if (buffer != NULL) {
        free(buffer);
    }
    H5Fclose(file_id);

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

    LLVMFuzzerTestOneInput_226(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
