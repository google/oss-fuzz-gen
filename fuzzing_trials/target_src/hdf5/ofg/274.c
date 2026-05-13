#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_274(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    // Prepare inputs for H5Fopen
    const char *filename = "/tmp/fuzzfile.h5";
    unsigned int access_flags = H5F_ACC_RDONLY;  // Read-only mode
    hid_t fapl_id = H5P_DEFAULT;

    // Write the fuzz data to the file
    FILE *file = fopen(filename, "wb");
    if (file == NULL) {
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Call the function-under-test
    hid_t file_id = H5Fopen(filename, access_flags, fapl_id);

    // Close the file if it was successfully opened
    if (file_id >= 0) {
        H5Fclose(file_id);
    }

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

    LLVMFuzzerTestOneInput_274(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
