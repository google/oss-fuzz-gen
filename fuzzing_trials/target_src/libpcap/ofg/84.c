#include <stdint.h>
#include <stddef.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_84(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Not enough data to extract an integer for snaplen
    }

    // Initialize a pcap_t structure
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcap == NULL) {
        return 0; // Failed to create pcap_t, return early
    }

    // Extract an integer from the input data for snaplen
    int snaplen = *(const int *)data;

    // Call the function-under-test
    pcap_set_snaplen(pcap, snaplen);

    // Clean up
    pcap_close(pcap);

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

    LLVMFuzzerTestOneInput_84(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
