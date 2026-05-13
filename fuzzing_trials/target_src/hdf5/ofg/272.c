#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_272(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0;
    }

    // Prepare the parameters for H5Fclose_async
    const char *app_file = "application_file";
    const char *app_func = "application_function";
    unsigned int app_line = (unsigned int)data[0]; // Use the first byte of data
    hid_t file_id = (hid_t)data[1]; // Use the second byte of data
    hid_t es_id = (hid_t)data[2]; // Use the third byte of data

    // Call the function-under-test
    herr_t result = H5Fclose_async(file_id, es_id);

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

    LLVMFuzzerTestOneInput_272(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
