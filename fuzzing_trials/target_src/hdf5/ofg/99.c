#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    hid_t file_id;
    unsigned int intent;
    herr_t status;

    // Ensure the input size is sufficient for a filename
    if (size < 1) {
        return 0;
    }

    // Create a temporary file to use with HDF5
    char filename[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(filename);
    if (fd == -1) {
        return 0;
    }
    close(fd);

    // Write data to the temporary file
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Open the HDF5 file
    file_id = H5Fopen(filename, H5F_ACC_RDONLY, H5P_DEFAULT);
    if (file_id < 0) {
        // Cleanup the temporary file
        remove(filename);
        return 0;
    }

    // Call the function-under-test
    status = H5Fget_intent(file_id, &intent);

    // Close the HDF5 file
    H5Fclose(file_id);

    // Cleanup the temporary file
    remove(filename);

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

    LLVMFuzzerTestOneInput_99(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
