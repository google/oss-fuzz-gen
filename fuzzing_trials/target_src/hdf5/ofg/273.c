#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_273(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract necessary parameters
    if (size < 3) {
        return 0;
    }

    // Extract parameters from the input data
    const char *app_file = __FILE__; // Use the current file name
    const char *app_func = __func__; // Use the current function name
    unsigned int app_line = __LINE__; // Use the current line number

    // Create dummy hid_t values
    hid_t es_id = (hid_t)data[1];
    hid_t file_id = (hid_t)data[2];

    // Call the function-under-test
    H5Fclose_async(file_id, es_id);

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

    LLVMFuzzerTestOneInput_273(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
