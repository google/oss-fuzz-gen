#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_128(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    // Initialize parameters for pcap_compile_nopcap
    int snaplen = 65535; // Typical maximum capture length
    int dlt = DLT_EN10MB; // Ethernet
    struct bpf_program fp;
    const char *filter_exp = (const char *)data; // Use fuzz data as filter expression
    int optimize = 1; // Enable optimization
    bpf_u_int32 netmask = 0xFFFFFF00; // Typical netmask for a local network

    // Ensure filter_exp is null-terminated
    char *null_terminated_filter = (char *)malloc(size + 1);
    if (null_terminated_filter == NULL) {
        return 0;
    }
    memcpy(null_terminated_filter, data, size);
    null_terminated_filter[size] = '\0';

    // Call the function-under-test
    pcap_compile_nopcap(snaplen, dlt, &fp, null_terminated_filter, optimize, netmask);

    // Free allocated memory
    free(null_terminated_filter);

    // Cleanup bpf_program if it was successfully compiled
    if (fp.bf_len > 0) {
        pcap_freecode(&fp);
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

    LLVMFuzzerTestOneInput_128(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
