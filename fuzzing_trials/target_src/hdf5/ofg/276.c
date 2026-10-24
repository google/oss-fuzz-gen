#include <stdint.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_276(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract a valid hid_t
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract a hid_t from the input data
    hid_t file_id = *(const hid_t *)data;

    // Initialize the H5AC_cache_config_t structure
    H5AC_cache_config_t config;
    config.version = H5AC__CURR_CACHE_CONFIG_VERSION; // Set to the current version

    // Call the function-under-test
    herr_t result = H5Fget_mdc_config(file_id, &config);

    // We don't need to do anything with the result for fuzzing purposes
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

    LLVMFuzzerTestOneInput_276(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
