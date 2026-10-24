#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_566(const uint8_t *data, size_t size) {
    if (size == 0) {
        return 0;
    }

    // Initialize the Janet runtime
    janet_init();

    // Initialize a Janet object from the input data
    Janet janet_obj = janet_wrap_string(janet_string(data, size));

    // Call the function-under-test
    JanetString result = janet_to_string(janet_obj);

    // Use the result to prevent compiler optimizations
    (void)result;

    // Clean up the Janet runtime
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

    LLVMFuzzerTestOneInput_566(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
