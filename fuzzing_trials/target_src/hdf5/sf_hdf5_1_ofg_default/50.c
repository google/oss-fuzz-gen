#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_50(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract a valid hid_t
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract a hid_t from the data
    hid_t loc_id = *(const hid_t *)data;

    // Initialize H5G_info_t structure
    H5G_info_t group_info;
    group_info.nlinks = 0;
    group_info.max_corder = 0;
    group_info.mounted = 0;

    // Call the function-under-test
    herr_t result = H5Gget_info(loc_id, &group_info);

    // Use the result to avoid compiler optimizations
    if (result < 0) {
        // Handle error case if necessary
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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_50(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
