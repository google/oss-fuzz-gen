#include <cstdint>
#include <cstdlib>

extern "C" {
    // Include the correct path for the header where tjPlaneHeight is declared
    #include "/src/libjpeg-turbo.main/src/turbojpeg.h"
}

// Function-under-test
extern "C" int tjPlaneHeight(int componentID, int height, int subsamp);

extern "C" int LLVMFuzzerTestOneInput_87(const uint8_t *data, size_t size) {
    if (size < 3) return 0; // Ensure there's enough data to read

    // Extract values from the input data
    int componentID = data[0] % 4; // Assuming componentID ranges from 0 to 3 for Y, U, V, etc.
    int height = data[1] + 1; // Ensure height is non-zero
    int subsamp = data[2] % 4; // Assuming subsampling options like TJ_420, TJ_422, etc.

    // Call the function-under-test with parameters extracted from the input data
    tjPlaneHeight(componentID, height, subsamp);

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

    LLVMFuzzerTestOneInput_87(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
