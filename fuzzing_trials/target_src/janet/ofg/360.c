#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Assuming the function is declared in a header file
int janet_scan_uint64(const uint8_t *, int32_t, uint64_t *);

int LLVMFuzzerTestOneInput_360(const uint8_t *data, size_t size) {
    // Ensure size is at least 1 to have a valid int32_t length
    if (size < 1) {
        return 0;
    }

    // Use the first byte to determine the length of the data to scan
    int32_t length = (int32_t)(data[0] % size);

    // Ensure the length is non-negative and does not exceed available size
    if (length < 0 || length > (int32_t)size) {
        length = (int32_t)size;
    }

    uint64_t result = 0;

    // Call the function-under-test
    janet_scan_uint64(data, length, &result);

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

    LLVMFuzzerTestOneInput_360(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
