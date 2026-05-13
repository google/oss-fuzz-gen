#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "ares.h"
#include <arpa/inet.h>

static void fuzz_ares_strerror(int code) {
    const char *error_message = ares_strerror(code);
    (void)error_message; // Suppress unused variable warning
}

static void fuzz_ares_inet_ntop(int af, const void *src, size_t src_size) {
    char dst[INET6_ADDRSTRLEN];
    if (src_size >= sizeof(struct in_addr) && af == AF_INET) {
        ares_inet_ntop(af, src, dst, INET_ADDRSTRLEN);
    } else if (src_size >= sizeof(struct in6_addr) && af == AF_INET6) {
        ares_inet_ntop(af, src, dst, INET6_ADDRSTRLEN);
    }
}

static void fuzz_ares_freeaddrinfo() {
    struct ares_addrinfo *ai = (struct ares_addrinfo *)malloc(sizeof(struct ares_addrinfo));
    if (!ai) return;

    ai->cnames = NULL;
    ai->nodes = NULL;
    ai->name = (char *)malloc(10); // Allocate some memory for the name
    if (ai->name) {
        strncpy(ai->name, "test", 10); // Initialize the allocated memory
    }

    // Free the allocated memory using ares_freeaddrinfo
    ares_freeaddrinfo(ai);
}

int LLVMFuzzerTestOneInput_31(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Fuzz ares_strerror
    int error_code = Data[0];
    fuzz_ares_strerror(error_code);

    // Fuzz ares_inet_ntop
    if (Size > 1) {
        int af = Data[1] % 3 == 0 ? AF_INET : AF_INET6; // Randomly choose between AF_INET and AF_INET6
        fuzz_ares_inet_ntop(af, Data + 2, Size - 2);
    }

    // Fuzz ares_freeaddrinfo
    fuzz_ares_freeaddrinfo();

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

    LLVMFuzzerTestOneInput_31(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
