#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "pcap/pcap.h"
#include <string.h>

int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    char *filter_exp;
    struct bpf_program program;
    pcap_t *handle;

    // Ensure the data is null-terminated for use as a string
    filter_exp = (char *)malloc(size + 1);
    if (!filter_exp) {
        return 0; // Exit if memory allocation fails
    }
    memcpy(filter_exp, data, size);
    filter_exp[size] = '\0';

    // Open a fake pcap handle (offline mode with no file)
    handle = pcap_open_dead(DLT_RAW, 65535);

    // Compile the filter expression
    if (pcap_compile(handle, &program, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == 0) {
        // Successfully compiled, now free the compiled program
        pcap_freecode(&program);
    }

    // Clean up
    pcap_close(handle);
    free(filter_exp);

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

    LLVMFuzzerTestOneInput_16(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
