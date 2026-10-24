#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_233(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract an hid_t value
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract an hid_t value from the input data
    hid_t attribute_id = *(const hid_t *)data;

    // Call the function-under-test
    hsize_t storage_size = H5Aget_storage_size(attribute_id);

    // Use the result in some way (e.g., print it, but here we just use it to avoid compiler warnings)
    (void)storage_size;

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

    LLVMFuzzerTestOneInput_233(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
