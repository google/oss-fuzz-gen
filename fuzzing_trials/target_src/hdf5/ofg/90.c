#include <stdint.h>
#include <stddef.h>
#include <hdf5.h>

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Declare and initialize the variables needed for the function call
    hid_t dataset_id = 0; // Assuming a valid dataset_id is 0 for fuzzing
    hsize_t coord[2] = {0, 0}; // Initialize with 0,0 for simplicity
    unsigned int filter_mask = 0;
    haddr_t addr = 0;
    hsize_t size_out = 0;

    // Ensure there's enough data to populate the coordinates
    if (size >= sizeof(hsize_t) * 2) {
        coord[0] = ((const hsize_t *)data)[0];
        coord[1] = ((const hsize_t *)data)[1];
    }

    // Call the function-under-test
    H5Dget_chunk_info_by_coord(dataset_id, coord, &filter_mask, &addr, &size_out);

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

    LLVMFuzzerTestOneInput_90(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
