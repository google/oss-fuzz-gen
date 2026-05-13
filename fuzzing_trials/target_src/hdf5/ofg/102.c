#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract necessary values
    if (size < sizeof(hid_t) + sizeof(haddr_t) + sizeof(hsize_t)) {
        return 0;
    }

    // Extract hid_t from data
    hid_t file_id = *(const hid_t *)data;
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    // Allocate and initialize haddr_t
    haddr_t addr = *(const haddr_t *)data;
    data += sizeof(haddr_t);
    size -= sizeof(haddr_t);

    // Allocate and initialize hsize_t
    hsize_t size_info = *(const hsize_t *)data;

    // Call the function-under-test
    herr_t result = H5Fget_mdc_image_info(file_id, &addr, &size_info);

    // Return 0 as the fuzzer harness should always return 0
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

    LLVMFuzzerTestOneInput_102(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
