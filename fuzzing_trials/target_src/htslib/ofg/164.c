#include <stdint.h>
#include <stddef.h>

// Include the correct header file for the function-under-test
#include "/src/htslib/htslib/hts.h"

// Function signature for the function-under-test
const char *hts_test_feature(unsigned int feature);

int LLVMFuzzerTestOneInput_164(const uint8_t *data, size_t size) {
    // Ensure there is enough data to read an unsigned int
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Extract an unsigned int from the input data
    unsigned int feature = *(const unsigned int *)data;

    // Call the function-under-test with the extracted feature
    const char *result = hts_test_feature(feature);

    // Optionally, perform some checks or operations on the result
    // For fuzzing purposes, we don't need to do anything further

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

    LLVMFuzzerTestOneInput_164(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
