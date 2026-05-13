#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_99(const uint8_t *data, size_t size) {
    pcap_t *pcap_handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Create a fake pcap_t handle using pcap_open_dead
    pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcap_handle == NULL) {
        return 0;
    }

    // Use the input data to create a pcap_pkthdr and a packet
    struct pcap_pkthdr header;
    header.len = size;
    header.caplen = size;
    header.ts.tv_sec = 0;
    header.ts.tv_usec = 0;

    // Check if the input data is non-empty
    if (size > 0) {
        // Process the packet using pcap_offline_filter
        struct bpf_program fp;
        if (pcap_compile(pcap_handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == 0) {
            pcap_offline_filter(&fp, &header, data);
            pcap_freecode(&fp);
        }
    }

    // Clean up
    pcap_close(pcap_handle);

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

    LLVMFuzzerTestOneInput_99(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
