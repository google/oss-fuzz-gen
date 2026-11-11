#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    if (size < sizeof(hid_t) * 3 + sizeof(hsize_t)) {
        return 0;
    }

    // Extract hid_t values from the input data
    hid_t dataset_id = *(const hid_t *)(data);
    hid_t type_id = *(const hid_t *)(data + sizeof(hid_t));
    hid_t space_id = *(const hid_t *)(data + 2 * sizeof(hid_t));

    // Extract hsize_t value from the input data
    hsize_t buf_size = *(const hsize_t *)(data + 3 * sizeof(hid_t));

    // Call the function-under-test
    herr_t result = H5Dvlen_get_buf_size(dataset_id, type_id, space_id, &buf_size);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result != 0) {
        // Handle error if needed
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

    LLVMFuzzerTestOneInput_21(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
