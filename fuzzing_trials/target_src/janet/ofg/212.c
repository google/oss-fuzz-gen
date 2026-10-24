#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

double janet_optnumber(const Janet *args, int32_t argc, int32_t n, double def);

int LLVMFuzzerTestOneInput_212(const uint8_t *data, size_t size) {
    if (size < sizeof(double) + sizeof(int32_t) * 2) {
        return 0;
    }

    // Initialize the Janet array
    Janet janet_args[1];
    double number;
    memcpy(&number, data, sizeof(double));
    janet_args[0] = janet_wrap_number(number);

    // Extract int32_t values from data
    int32_t argc;
    memcpy(&argc, data + sizeof(double), sizeof(int32_t));
    int32_t n;
    memcpy(&n, data + sizeof(double) + sizeof(int32_t), sizeof(int32_t));

    // Ensure argc is within bounds
    if (argc < 0 || argc > 1) {
        return 0;
    }

    // Extract default double value
    double def;
    memcpy(&def, data + sizeof(double) + sizeof(int32_t) * 2, sizeof(double));

    // Call the function-under-test
    double result = janet_optnumber(janet_args, argc, n, def);

    // Use the result in some way to avoid optimization out
    (void)result;

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

    LLVMFuzzerTestOneInput_212(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
