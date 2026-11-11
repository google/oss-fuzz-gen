#include <cstdint>
#include <cstdlib>
#include <cstdio>

// Assuming the function is defined in an external C library
extern "C" {
    unsigned long TJBUFSIZEYUV(int width, int height, int subsamp);
}

extern "C" int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract integers from the input data
    int width = *(reinterpret_cast<const int*>(data));
    int height = *(reinterpret_cast<const int*>(data + sizeof(int)));
    int subsamp = *(reinterpret_cast<const int*>(data + 2 * sizeof(int)));

    // Call the function-under-test
    unsigned long result = TJBUFSIZEYUV(width, height, subsamp);

    // Print the result for debugging purposes
    // (Optional, can be removed if not needed)
    printf("TJBUFSIZEYUV(%d, %d, %d) = %lu\n", width, height, subsamp, result);

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

    LLVMFuzzerTestOneInput_101(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
