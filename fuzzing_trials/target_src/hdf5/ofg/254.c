#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_254(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < 5) return 0;

    // Extract parts of the data for each parameter
    hid_t attr_id = (hid_t)data[0];
    hid_t es_id = (hid_t)data[1];

    // Call the function-under-test
    H5Aclose_async(attr_id, es_id);

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

    LLVMFuzzerTestOneInput_254(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
