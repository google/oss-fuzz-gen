#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    pcap_t *pcap;
    struct bpf_program fp;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *filter_exp;
    int optimize = 1;
    bpf_u_int32 net = 0;

    // Ensure data is null-terminated for use as a string
    filter_exp = (char *)malloc(size + 1);
    if (filter_exp == NULL) {
        return 0;
    }
    memcpy(filter_exp, data, size);
    filter_exp[size] = '\0';

    // Open a fake pcap handle for testing
    pcap = pcap_open_dead(DLT_RAW, 65535);
    if (pcap == NULL) {
        free(filter_exp);
        return 0;
    }

    // Call the function-under-test
    pcap_compile(pcap, &fp, filter_exp, optimize, net);

    // Clean up
    pcap_close(pcap);
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

    LLVMFuzzerTestOneInput_39(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
