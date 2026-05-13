#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_182(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    hid_t dataset_id = 1; // Assuming a valid dataset ID for testing
    hid_t fspace_id = 1;  // Assuming a valid file space ID for testing
    hsize_t nchunks = 0;

    // Call the function-under-test
    herr_t result = H5Dget_num_chunks(dataset_id, fspace_id, &nchunks);

    // Use the result or nchunks as needed (for fuzzing, we just call the function)
    (void)result; // Suppress unused variable warning

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

    LLVMFuzzerTestOneInput_182(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
