#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include "janet.h"

extern JanetAbstract janet_checkfile(Janet);

int LLVMFuzzerTestOneInput_369(const uint8_t *data, size_t size) {
    Janet janet_data;
    JanetAbstract result;

    // Initialize the Janet VM
    janet_init();

    // Ensure the size is sufficient to create a valid Janet string
    if (size == 0) {
        janet_deinit();
        return 0;
    }

    // Create a Janet string from the input data
    janet_data = janet_stringv((const uint8_t *)data, size);

    // Call the function-under-test
    result = janet_checkfile(janet_data);

    // Use the result to prevent compiler optimizations from removing the call
    if (result != NULL) {
        // Do something with the result if needed
    }

    // Deinitialize the Janet VM
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

    LLVMFuzzerTestOneInput_369(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
