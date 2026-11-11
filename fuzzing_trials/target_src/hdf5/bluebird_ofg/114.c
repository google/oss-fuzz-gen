#include <sys/stat.h>
#include <stdint.h>
#include <string.h>
#include "hdf5.h"

int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract the necessary parameters
    if (size < sizeof(hid_t) + sizeof(H5F_scope_t)) {
        return 0;
    }

    // Extract hid_t from the input data
    hid_t file_id;
    memcpy(&file_id, data, sizeof(hid_t));

    // Extract H5F_scope_t from the input data
    H5F_scope_t scope;
    memcpy(&scope, data + sizeof(hid_t), sizeof(H5F_scope_t));

    // Call the function-under-test
    herr_t result = H5Fflush(file_id, scope);

    // Return 0 to indicate the fuzzer can continue
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

    LLVMFuzzerTestOneInput_114(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
