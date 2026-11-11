#include <stdint.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to extract two values
    if (size < sizeof(hid_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Extract hid_t and unsigned int from the input data
    hid_t obj_id = *(const hid_t *)data;
    unsigned int idx = *(const unsigned int *)(data + sizeof(hid_t));

    // Call the function-under-test
    hid_t result = H5Aopen_idx(obj_id, idx);

    // Close the attribute if it was successfully opened
    if (result >= 0) {
        H5Aclose(result);
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

    LLVMFuzzerTestOneInput_3(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
