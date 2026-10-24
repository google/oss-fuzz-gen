#include <stdint.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_183(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract a valid hid_t
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract a hid_t from the input data
    hid_t file_id = *((hid_t *)data);

    // Call the function-under-test
    herr_t result = H5Freset_mdc_hit_rate_stats(file_id);

    // Use the result to avoid compiler optimizations
    (void)result;

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

    LLVMFuzzerTestOneInput_183(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
