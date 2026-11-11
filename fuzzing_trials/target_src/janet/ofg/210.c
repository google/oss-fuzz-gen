#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

extern int janet_scan_number(const uint8_t *, int32_t, double *);

int LLVMFuzzerTestOneInput_210(const uint8_t *data, size_t size) {
    // Ensure the size is at least 1 to have a valid int32_t length
    if (size < 1) {
        return 0;
    }

    // Use the first byte of data as the length for the function
    int32_t length = (int32_t)(data[0]);

    // Ensure length does not exceed the size of the remaining data
    if (length > (int32_t)(size - 1)) {
        length = (int32_t)(size - 1);
    }

    // Initialize a double to store the result
    double result;

    // Call the function-under-test
    janet_scan_number(data + 1, length, &result);

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

    LLVMFuzzerTestOneInput_210(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
