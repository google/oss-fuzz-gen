#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_153(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t file_id;
    hsize_t increment_size;

    // Ensure size is large enough to extract values
    if (size < sizeof(hid_t) + sizeof(hsize_t)) {
        return 0;
    }

    // Extract values from the input data
    file_id = *((hid_t *)data);
    increment_size = *((hsize_t *)(data + sizeof(hid_t)));

    // Call the function-under-test
    H5Fincrement_filesize(file_id, increment_size);

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

    LLVMFuzzerTestOneInput_153(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
