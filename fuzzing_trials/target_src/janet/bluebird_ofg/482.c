#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

extern const char *janet_optcbytes(const Janet *argv, int32_t n, int32_t argc, const char *dflt);

int LLVMFuzzerTestOneInput_482(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    Janet *argv = NULL;
    int32_t n = 0;
    int32_t argc = 1;
    const char *dflt = "default";

    // Ensure there is data to work with
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Allocate memory for Janet array
    argv = (Janet *)malloc(size);
    if (!argv) {
        return 0;
    }

    // Copy data into the Janet array
    memcpy(argv, data, size);

    // Call the function-under-test
    const char *result = janet_optcbytes(argv, n, argc, dflt);

    // Free allocated memory
    free(argv);

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_482(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
