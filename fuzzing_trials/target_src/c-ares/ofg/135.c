#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include "ares.h"

int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    /* Define address family */
    int af = data[0] % 2 == 0 ? AF_INET : AF_INET6;

    /* Ensure src is null-terminated */
    char src[INET6_ADDRSTRLEN];
    size_t src_size = size - 1 < INET6_ADDRSTRLEN - 1 ? size - 1 : INET6_ADDRSTRLEN - 1;
    memcpy(src, data + 1, src_size);
    src[src_size] = '\0';

    /* Define destination buffer */
    unsigned char dst[16];  // Enough to hold an IPv6 address

    /* Call the function-under-test */
    ares_inet_pton(af, src, dst);

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

    LLVMFuzzerTestOneInput_135(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
