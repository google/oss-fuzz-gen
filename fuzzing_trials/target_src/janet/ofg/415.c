#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_415(const uint8_t *data, size_t size) {
    // Initialize Janet VM if necessary
    janet_init();

    // Ensure that the size is sufficient to create two Janet objects
    if (size < 2 * sizeof(Janet)) {
        return 0;
    }

    // Create two Janet objects from the input data
    Janet janet1 = janet_wrap_integer(data[0]); // Using the first byte as an integer
    Janet janet2 = janet_wrap_integer(data[1]); // Using the second byte as an integer

    // Call the function-under-test
    Janet result = janet_next(janet1, janet2);

    // Optionally, you can inspect or use the result
    (void)result; // Suppress unused variable warning

    // Clean up Janet VM if necessary
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

    LLVMFuzzerTestOneInput_415(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
