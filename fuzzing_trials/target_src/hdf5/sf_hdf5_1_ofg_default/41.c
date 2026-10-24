#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t loc_id;
    H5G_info_t group_info;

    // Ensure size is sufficient to extract a valid loc_id
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract loc_id from the input data
    loc_id = *(hid_t *)data;

    // Call the function-under-test
    herr_t result = H5Gget_info(loc_id, &group_info);

    // Use the result to avoid compiler optimizations
    if (result < 0) {
        // Handle error if needed
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

    LLVMFuzzerTestOneInput_41(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
