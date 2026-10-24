#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_371(const uint8_t *data, size_t size) {
    // Ensure the data is null-terminated to be used as a C string
    char *null_terminated_data = (char *)malloc(size + 1);
    if (null_terminated_data == NULL) {
        return 0;
    }
    memcpy(null_terminated_data, data, size);
    null_terminated_data[size] = '\0';

    // Ensure the input is not empty to avoid crashing the function under test
    if (size == 0) {
        free(null_terminated_data);
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Call the function-under-test
    JanetSymbol symbol = janet_csymbol(null_terminated_data);

    // Free the allocated memory
    free(null_terminated_data);

    // Deinitialize the Janet environment
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

    LLVMFuzzerTestOneInput_371(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
