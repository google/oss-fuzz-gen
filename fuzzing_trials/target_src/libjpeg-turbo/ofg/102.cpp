#include <cstdint>
#include <cstdlib>
#include <cstdio>

extern "C" {
    // Declaration of the function-under-test
    unsigned long TJBUFSIZEYUV(int width, int height, int subsamp);
}

extern "C" int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract three integers from the input data
    int width = static_cast<int>(data[0]) + 1;  // Ensure width is at least 1
    int height = static_cast<int>(data[1]) + 1; // Ensure height is at least 1
    int subsamp = static_cast<int>(data[2]) % 4; // Assuming subsamp is between 0 and 3

    // Call the function-under-test
    unsigned long result = TJBUFSIZEYUV(width, height, subsamp);

    // Print the result to ensure the function is called
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

    LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
