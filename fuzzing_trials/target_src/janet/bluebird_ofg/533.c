#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>

// Assume that the function is declared in some header file
int janet_scan_number_base(const uint8_t *str, int32_t len, int32_t base, double *out);

int LLVMFuzzerTestOneInput_533(const uint8_t *data, size_t size) {
    // Ensure that the input size is at least 1 to avoid empty strings
    if (size < 1) {
        return 0;
    }

    // Prepare the parameters for the function-under-test
    const uint8_t *str = data;
    int32_t len = (int32_t)size;
    int32_t base = 10; // Using a common base for numbers, can vary this for fuzzing
    double out = 0.0;

    // Call the function-under-test
    janet_scan_number_base(str, len, base, &out);

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

    LLVMFuzzerTestOneInput_533(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
