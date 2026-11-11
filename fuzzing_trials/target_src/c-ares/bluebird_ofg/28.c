#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>  // Include this for malloc and free
#include "ares.h"

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    /* Ensure data is null-terminated */
    char *src = (char *)malloc(size + 1);
    if (!src) {
        return 0;
    }
    memcpy(src, data, size);
    src[size] = '\0';

    /* Prepare destination buffer */
    struct in6_addr dst;

    /* Test with AF_INET (IPv4) */
    ares_inet_pton(AF_INET, src, &dst);

    /* Test with AF_INET6 (IPv6) */
    ares_inet_pton(AF_INET6, src, &dst);

    free(src);
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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
