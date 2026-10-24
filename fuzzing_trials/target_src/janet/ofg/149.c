#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_149(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an int32_t for count
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Initialize Janet
    janet_init();

    // Create a JanetArray
    JanetArray *array = janet_array(10);

    // Extract an int32_t value from the data for count
    int32_t count;
    memcpy(&count, data, sizeof(int32_t));

    // Call the function-under-test
    janet_array_setcount(array, count);

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

    LLVMFuzzerTestOneInput_149(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
