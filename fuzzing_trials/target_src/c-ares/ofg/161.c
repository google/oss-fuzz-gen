#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ares.h>

int LLVMFuzzerTestOneInput_161(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    /* Extract the address family from the input data */
    int af = data[0] % 2 == 0 ? AF_INET : AF_INET6;

    /* Prepare the source buffer */
    unsigned char src[16] = {0}; // 16 bytes to accommodate both IPv4 and IPv6
    size_t src_size = (af == AF_INET) ? 4 : 16;

    if (size < 1 + src_size) {
        return 0;
    }

    /* Copy the appropriate number of bytes to the source buffer */
    memcpy(src, data + 1, src_size);

    /* Prepare the destination buffer */
    char dst[INET6_ADDRSTRLEN] = {0}; // INET6_ADDRSTRLEN is large enough for both IPv4 and IPv6

    /* Call the function-under-test */
    ares_inet_ntop(af, src, dst, INET6_ADDRSTRLEN);

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

    LLVMFuzzerTestOneInput_161(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
