#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_160(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract parameters
    if (size < sizeof(hid_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Extract parameters from the input data
    hid_t file_id = *((hid_t *)data);
    unsigned int types = *((unsigned int *)(data + sizeof(hid_t)));

    // Call the function-under-test
    ssize_t obj_count = H5Fget_obj_count(file_id, types);

    // Use the result in some way to avoid compiler optimizations
    (void)obj_count;

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

    LLVMFuzzerTestOneInput_160(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
