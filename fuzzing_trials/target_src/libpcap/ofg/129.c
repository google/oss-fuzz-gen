#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

int LLVMFuzzerTestOneInput_129(const uint8_t *data, size_t size) {
    // Define and initialize variables
    int snaplen = 65535; // Maximum capture length
    int linktype = DLT_EN10MB; // Ethernet link layer type
    struct bpf_program fp; // BPF program structure
    char filter_exp[256] = ""; // Filter expression
    int optimize = 1; // Optimization flag
    bpf_u_int32 netmask = 0xffffff; // Netmask

    // Ensure the filter expression is null-terminated and within bounds
    if (size < sizeof(filter_exp)) {
        memcpy(filter_exp, data, size);
        filter_exp[size] = '\0';
    } else {
        memcpy(filter_exp, data, sizeof(filter_exp) - 1);
        filter_exp[sizeof(filter_exp) - 1] = '\0';
    }

    // Call the function-under-test
    pcap_compile_nopcap(snaplen, linktype, &fp, filter_exp, optimize, netmask);

    // Free the allocated memory for BPF program
    pcap_freecode(&fp);

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

    LLVMFuzzerTestOneInput_129(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
