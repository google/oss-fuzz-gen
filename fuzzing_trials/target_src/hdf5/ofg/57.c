#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract necessary parameters
    if (size < 10) {
        return 0;
    }

    // Extract parameters from the input data
    const char *name1 = "dataset1";
    const char *name2 = "dataset2";
    unsigned int flags = (unsigned int)data[0];
    hid_t loc_id = (hid_t)data[1];
    hid_t type_id = (hid_t)data[2];
    hid_t space_id = (hid_t)data[3];
    hid_t dcpl_id = (hid_t)data[4];
    hid_t dapl_id = (hid_t)data[5];
    hid_t es_id = (hid_t)data[6];
    hid_t dxpl_id = (hid_t)data[7];

    // Call the function-under-test
    hid_t result = H5Dcreate_async(loc_id, name1, type_id, space_id, dcpl_id, dapl_id, es_id, dxpl_id);

    // Use the result to avoid unused variable warning
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

    LLVMFuzzerTestOneInput_57(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
