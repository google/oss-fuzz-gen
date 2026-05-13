#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_233(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Use the first byte of data to determine the boolean value
    int boolean_value = data[0] % 2; // This will give either 0 or 1

    // Call the function-under-test using the macro
    Janet result = janet_wrap_boolean(boolean_value);

    // Optionally, you can add some checks or operations on the result
    // For example, you could check if the result is a valid Janet type
    // However, the main purpose here is to call the function

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

    LLVMFuzzerTestOneInput_233(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
