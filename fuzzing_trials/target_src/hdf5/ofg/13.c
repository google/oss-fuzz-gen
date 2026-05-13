#include <stdint.h>
#include <hdf5.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_13(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for a hid_t (typically an integer)
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract a hid_t from the input data
    hid_t object_id = *(const hid_t *)data;

    // Call the function-under-test
    int num_attrs = H5Aget_num_attrs(object_id);

    // Print the result for debugging purposes (optional)
    printf("Number of attributes: %d\n", num_attrs);

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

    LLVMFuzzerTestOneInput_13(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
