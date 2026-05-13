#include <stdint.h>
#include <stddef.h>  // Include for size_t
#include <hdf5.h>

int LLVMFuzzerTestOneInput_152(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract two values
    if (size < sizeof(hid_t) + sizeof(hsize_t)) {
        return 0;
    }

    // Extract the first part of the data as hid_t
    hid_t file_id = *(const hid_t *)data;
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    // Extract the second part of the data as hsize_t
    hsize_t increment_size = *(const hsize_t *)data;

    // Call the function-under-test
    herr_t result = H5Fincrement_filesize(file_id, increment_size);

    // Return 0 to indicate the fuzzer can continue
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

    LLVMFuzzerTestOneInput_152(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
