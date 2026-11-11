#include <cstdint>
#include <cstdlib>
#include <cstdio>

// Assuming the function is defined in an external C library
extern "C" {
    int tj3YUVPlaneHeight(int componentID, int imageHeight, int subsampling);
}

extern "C" int LLVMFuzzerTestOneInput_83(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract integers from the input data
    int componentID = static_cast<int>(data[0]);
    int imageHeight = static_cast<int>(data[1]);
    int subsampling = static_cast<int>(data[2]);

    // Call the function-under-test
    int result = tj3YUVPlaneHeight(componentID, imageHeight, subsampling);

    // Print the result (optional, for debugging purposes)
    printf("Result: %d\n", result);

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

    LLVMFuzzerTestOneInput_83(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
