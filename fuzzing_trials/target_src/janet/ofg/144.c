#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>

// Assuming the function is declared in some header file
// int janet_scan_int64(const uint8_t *, int32_t, int64_t *);

extern int janet_scan_int64(const uint8_t *, int32_t, int64_t *);

int LLVMFuzzerTestOneInput_144(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to be used as an int32_t
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Cast size to int32_t for the function parameter
    int32_t length = (int32_t)size;

    // Initialize the int64_t variable to store the result
    int64_t result = 0;

    // Call the function under test
    janet_scan_int64(data, length, &result);

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

    LLVMFuzzerTestOneInput_144(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
