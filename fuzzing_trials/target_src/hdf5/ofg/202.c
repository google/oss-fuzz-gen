#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_202(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the parameters
    if (size < 3) {
        return 0;
    }

    // Initialize parameters
    hid_t attribute_id = (hid_t)data[0];
    hid_t mem_type_id = (hid_t)data[1];
    const void *buf = (const void *)(data + 2);
    hid_t es_id = (hid_t)(size - 2);

    // Call the function-under-test
    herr_t result = H5Awrite_async(attribute_id, mem_type_id, buf, es_id);

    // Handle the result if necessary (for fuzzing, usually just return 0)
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

    LLVMFuzzerTestOneInput_202(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
