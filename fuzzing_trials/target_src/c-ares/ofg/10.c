#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_10(const unsigned char *data, size_t size) {
    // Ensure there is enough data to split between `encoded` and `abuf`
    if (size < 2) return 0;

    // Split the data into two parts for `encoded` and `abuf`
    size_t encoded_size = size / 2;
    size_t abuf_size = size - encoded_size;

    const unsigned char *encoded = data;
    const unsigned char *abuf = data + encoded_size;

    // Allocate memory for the output parameters
    unsigned char *s = NULL;
    long enclen = 0;

    // Call the function-under-test
    ares_expand_string(encoded, abuf, (int)abuf_size, &s, &enclen);

    // Free allocated memory for `s` if it was set
    if (s != NULL) {
        free(s);
    }

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
