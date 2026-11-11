#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    // Ensure there is enough data to create a Janet array with at least one element
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Create a Janet array from the input data
    Janet *janetArray = (Janet *)data;

    // Use the first 4 bytes of the data for the index, ensuring it's within bounds
    int32_t index = 0;
    if (size >= sizeof(Janet) + sizeof(int32_t)) {
        index = *(int32_t *)(data + sizeof(Janet));
    }
    index = index % (size / sizeof(Janet)); // Ensure index is within bounds

    // Call the function-under-test
    double result = janet_getnumber(janetArray, index);

    // Use the result to avoid compiler optimizations removing the call
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

    LLVMFuzzerTestOneInput_62(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
