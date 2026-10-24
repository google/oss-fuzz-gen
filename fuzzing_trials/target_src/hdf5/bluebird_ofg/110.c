#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_110(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to extract the necessary parts
    if (size < 4) {
        return 0;
    }

    // Extract the first byte for H5L_type_t
    H5L_type_t link_type = (H5L_type_t)(data[0] % 3); // Assuming 3 types for simplicity

    // Extract the next byte for hid_t
    hid_t loc_id = (hid_t)(data[1]);

    // Use the remaining data for the link_name and target_name
    size_t half_size = (size - 2) / 2;
    char *link_name = (char *)malloc(half_size + 1);
    char *target_name = (char *)malloc(half_size + 1);

    if (link_name == NULL || target_name == NULL) {
        free(link_name);
        free(target_name);
        return 0;
    }

    memcpy(link_name, data + 2, half_size);
    link_name[half_size] = '\0';

    memcpy(target_name, data + 2 + half_size, half_size);
    target_name[half_size] = '\0';

    // Call the function-under-test
    herr_t result = H5Glink(loc_id, link_type, link_name, target_name);

    // Clean up
    free(link_name);
    free(target_name);

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

    LLVMFuzzerTestOneInput_110(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
