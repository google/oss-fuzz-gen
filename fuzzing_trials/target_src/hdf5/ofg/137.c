#include <stdint.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
    // Ensure we have enough data to create a valid hid_t
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Interpret the first few bytes of data as a hid_t
    hid_t attribute_id = *(const hid_t *)data;

    // Call the function-under-test
    hid_t type_id = H5Aget_type(attribute_id);

    // If the type_id is valid, close it to avoid resource leaks
    if (type_id >= 0) {
        H5Tclose(type_id);
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

    LLVMFuzzerTestOneInput_137(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
