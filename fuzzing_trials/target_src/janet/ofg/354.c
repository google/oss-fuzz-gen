#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_354(const uint8_t *data, size_t size) {
    if (size < 2 * sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet
    janet_init();

    // Create two Janet values from the input data
    Janet x, y;
    memcpy(&x, data, sizeof(Janet));
    memcpy(&y, data + sizeof(Janet), sizeof(Janet));

    // Call the function-under-test
    Janet result = janet_in(x, y);

    // Clean up Janet
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

    LLVMFuzzerTestOneInput_354(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
