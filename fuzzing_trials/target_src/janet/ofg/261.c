#include <stddef.h>  // Include for size_t
#include <stdint.h>  // Include for uint8_t and int32_t
#include <stdlib.h>  // Include for abort

extern void janet_fixarity(int32_t, int32_t);

int LLVMFuzzerTestOneInput_261(const uint8_t *data, size_t size) {
    if (size < 8) {
        return 0; // Ensure there's enough data to extract two int32_t values
    }

    // Extract two int32_t values from the input data
    int32_t arg1 = (int32_t)((data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]);
    int32_t arg2 = (int32_t)((data[4] << 24) | (data[5] << 16) | (data[6] << 8) | data[7]);

    // Validate extracted values to avoid potential issues in janet_fixarity
    // For instance, ensure that the values are within a specific range if needed
    // This is a placeholder; modify as per the actual requirements of janet_fixarity
    if (arg1 < -1000 || arg1 > 1000 || arg2 < -1000 || arg2 > 1000) {
        return 0;
    }

    // Call the function-under-test
    janet_fixarity(arg1, arg2);

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

    LLVMFuzzerTestOneInput_261(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
