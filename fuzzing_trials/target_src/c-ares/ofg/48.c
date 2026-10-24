#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_48(const unsigned char *data, size_t size) {
    // Ensure the data size is sufficient for extracting parameters
    if (size < 6) {
        return 0;
    }

    // Extract parameters from the input data
    const char *name = (const char *)data;
    int dnsclass = (int)data[0];
    int type = (int)data[1];
    unsigned short id = (unsigned short)((data[2] << 8) | data[3]);
    int rd = (int)data[4];

    // Allocate memory for the buffer
    unsigned char *buf = NULL;
    int buflen = 0;

    // Call the function-under-test
    ares_mkquery(name, dnsclass, type, id, rd, &buf, &buflen);

    // Free allocated buffer if not NULL
    if (buf) {
        free(buf);
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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
