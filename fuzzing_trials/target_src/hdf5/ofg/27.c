#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_27(const uint8_t *data, size_t size) {
    // Ensure data is large enough to extract necessary parameters
    if (size < sizeof(hid_t) + sizeof(unsigned int) + sizeof(hsize_t)) {
        return 0;
    }

    // Extract parameters from data
    unsigned int flags = *((unsigned int *)data);
    data += sizeof(unsigned int);

    hid_t dset_id = *((hid_t *)data);
    data += sizeof(hid_t);

    hsize_t extent = *((hsize_t *)data);

    // Create an array for extent
    hsize_t extents[] = {extent};

    // Create a valid event set ID
    hid_t es_id = H5EScreate();

    // Call the function-under-test with the correct number of arguments
    H5Dset_extent_async(dset_id, extents, es_id);

    // Close the event set ID
    H5ESclose(es_id);

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

    LLVMFuzzerTestOneInput_27(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
