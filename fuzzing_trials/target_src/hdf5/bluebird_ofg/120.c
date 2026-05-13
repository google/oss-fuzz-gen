#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include "hdf5.h"

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract the necessary parameters
    if (size < sizeof(hid_t) + sizeof(hsize_t) + sizeof(unsigned int) + sizeof(haddr_t) + sizeof(hsize_t)) {
        return 0;
    }

    // Initialize variables
    hid_t dataset_id = *((hid_t *)data);
    data += sizeof(hid_t);
    size -= sizeof(hid_t);

    const hsize_t *coord = (const hsize_t *)data;
    data += sizeof(hsize_t);
    size -= sizeof(hsize_t);

    unsigned int filter_mask;
    haddr_t addr;
    hsize_t size_out;

    // Call the function-under-test
    herr_t result = H5Dget_chunk_info_by_coord(dataset_id, coord, &filter_mask, &addr, &size_out);

    // Use the result to prevent compiler optimizations from removing the function call
    (void)result;

    return 0;
}

#ifdef __cplusplus
}
#endif
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

    LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
