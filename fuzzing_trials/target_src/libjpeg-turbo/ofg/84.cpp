#include <cstdint>
#include <cstdlib>

// Include the necessary header for the function-under-test
extern "C" {
    int tj3YUVPlaneHeight(int componentID, int width, int subsampling);
}

extern "C" int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract three integers from the input data
    int componentID = static_cast<int>(data[0] % 4); // Typically 0, 1, or 2 for Y, U, V
    int width = static_cast<int>(data[1]) + 1; // Ensure width is non-zero
    int subsampling = static_cast<int>(data[2] % 5); // Subsampling values typically range from 0 to 4

    // Call the function-under-test
    tj3YUVPlaneHeight(componentID, width, subsampling);

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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
