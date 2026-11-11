#include <hdf5.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_201(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < 10) return 0;

    // Extract parameters from data
    hid_t attr_id = (hid_t)data[0];
    hid_t type_id = (hid_t)data[1];
    hid_t es_id = (hid_t)data[2];
    
    // Ensure the rest of the data is not empty
    if (size <= 3) return 0;
    
    // Use remaining data as the buffer for the void pointer
    const void *buf = (const void *)(data + 3);
    size_t buf_size = size - 3;

    // Call the function-under-test
    herr_t result = H5Awrite_async(attr_id, type_id, buf, es_id);

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

    LLVMFuzzerTestOneInput_201(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
