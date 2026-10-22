#include <stdint.h>
#include <stdlib.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Declare and initialize the necessary variables
    hid_t loc_id = 0; // Assuming a valid location ID is 0 for this example
    H5G_info_t group_info;

    // Ensure that the input size is large enough to simulate a valid input
    if (size < sizeof(hid_t)) {
        return 0;
    }

    // Use the input data to simulate a valid loc_id
    loc_id = *((hid_t *)data);

    // Call the function-under-test
    herr_t result = H5Gget_info(loc_id, &group_info);

    // Check the result (optional)
    if (result < 0) {
        // Handle error (if necessary)
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

    LLVMFuzzerTestOneInput_49(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
