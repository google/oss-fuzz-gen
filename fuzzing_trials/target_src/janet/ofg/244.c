#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_244(const uint8_t *data, size_t size) {
    // Initialize Janet
    janet_init();

    // Create a JanetArray with some initial capacity
    JanetArray *array = janet_array(10);

    // Fill the array with data from the input, ensuring we don't exceed the size
    for (size_t i = 0; i < size && i < 10; i++) {
        // Convert each byte to a Janet integer and put it in the array
        janet_array_push(array, janet_wrap_integer(data[i]));
    }

    // Call the function-under-test
    Janet result = janet_wrap_array(array);

    // Use the result to avoid any compiler optimizations that might skip the call
    (void)result;

    // Clean up
    janet_deinit();

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

    LLVMFuzzerTestOneInput_244(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
