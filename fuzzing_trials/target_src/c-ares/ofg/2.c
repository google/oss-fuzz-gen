#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_2(const unsigned char *data, size_t size) {
    // Ensure the data is large enough to extract required parameters
    if (size < 4) {
        return 0;
    }

    // Extract parameters from the data
    const char *name = (const char *)data;
    int dnsclass = (int)data[0];
    int type = (int)data[1];
    unsigned short id = (unsigned short)data[2];
    int rd = (int)data[3];
    int max_udp_size = 512; // Typical max UDP size for DNS queries

    // Prepare output parameters
    unsigned char *bufp = NULL;
    int buflenp = 0;

    // Call the function-under-test
    ares_create_query(name, dnsclass, type, id, rd, &bufp, &buflenp, max_udp_size);

    // Free allocated buffer if it was allocated
    if (bufp) {
        free(bufp);
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

    LLVMFuzzerTestOneInput_2(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
