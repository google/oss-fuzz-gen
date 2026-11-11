#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_43(const uint8_t *data, size_t size) {
    hid_t loc_id;
    H5G_info_t group_info;
    herr_t status;

    // Ensure that the size is large enough to simulate a valid loc_id
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Extract a hid_t value from the input data
    loc_id = *((hid_t *)data);

    // Initialize group_info structure
    group_info.nlinks = 0;
    group_info.max_corder = 0;
    group_info.mounted = 0;

    // Call the function-under-test
    status = H5Gget_info(loc_id, &group_info);

    // You can add checks or further processing based on the status here if needed

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

    LLVMFuzzerTestOneInput_43(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
