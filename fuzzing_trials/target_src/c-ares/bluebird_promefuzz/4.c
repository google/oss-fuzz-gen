#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/select.h>
#include "ares.h"

static void fuzz_ares_destroy(ares_channel channel) {
    ares_destroy(channel);
}

static int fuzz_ares_expand_name(const unsigned char *encoded, const unsigned char *abuf, int alen) {
    char *s = NULL;
    long enclen = 0;
    int result = ares_expand_name(encoded, abuf, alen, &s, &enclen);
    if (result == ARES_SUCCESS) {
        ares_free_string(s);
    }
    return result;
}

static int fuzz_ares_expand_string(const unsigned char *encoded, const unsigned char *abuf, int alen) {
    unsigned char *s = NULL;
    long enclen = 0;
    int result = ares_expand_string(encoded, abuf, alen, &s, &enclen);
    if (result == ARES_SUCCESS) {
        ares_free_string(s);
    }
    return result;
}

static int fuzz_ares_fds(ares_channel channel) {
    fd_set read_fds, write_fds;
    FD_ZERO(&read_fds);
    FD_ZERO(&write_fds);
    return ares_fds(channel, &read_fds, &write_fds);
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    ares_channel channel;
    int status = ares_init(&channel);
    if (status != ARES_SUCCESS) {
        return 0;
    }

    if (Size > 2) {
        fuzz_ares_expand_name(Data, Data, Size);
    }

    if (Size > 1) {
        fuzz_ares_expand_string(Data, Data, Size);
    }

    fuzz_ares_fds(channel);

    fuzz_ares_destroy(channel);
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
