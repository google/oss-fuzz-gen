#include <stdint.h>
#include <stddef.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    // Define and initialize the parameters for pcap_open_dead
    int linktype = DLT_EN10MB; // Ethernet
    int snaplen = 65535; // Maximum capture length

    // Call the function-under-test
    pcap_t *handle = pcap_open_dead(linktype, snaplen);

    // Check if the handle is not NULL
    if (handle != NULL) {
        // Create a pcap_pkthdr structure to hold the packet header
        struct pcap_pkthdr header;
        header.caplen = size;
        header.len = size;

        // Use the data as a packet and process it with pcap_offline_filter
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) != -1) {
            pcap_offline_filter(&fp, &header, data);
            pcap_freecode(&fp);
        }

        // Close the handle
        pcap_close(handle);
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

    LLVMFuzzerTestOneInput_121(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
