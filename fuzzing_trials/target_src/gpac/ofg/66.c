#include <stdint.h>
#include <stddef.h>
#include <gpac/isomedia.h>  // Assuming the function is part of the GPAC library

int LLVMFuzzerTestOneInput_66(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract an index
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Extract the index from the input data
    uint32_t idx = *(const uint32_t *)data;

    // Check if the index is within a valid range
    // Assuming we have a function or a constant that defines the max valid index
    // For illustration, let's assume the maximum valid index is 1000
    const uint32_t MAX_VALID_INDEX = 1000;
    if (idx > MAX_VALID_INDEX) {
        return 0;
    }

    // Call the function-under-test
    gf_isom_get_supported_box_type(idx);

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

    LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
