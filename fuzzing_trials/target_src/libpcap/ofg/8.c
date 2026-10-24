#include <stdint.h>
#include <stddef.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_8(const uint8_t *data, size_t size) {
    pcap_t *pcap_handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open a fake pcap handle for testing
    pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcap_handle == NULL) {
        return 0;
    }

    // Ensure the size is at least 1 to extract a valid integer
    int immediate_mode = 0;
    if (size > 0) {
        immediate_mode = (int)data[0]; // Use the first byte for the immediate_mode
    }

    // Call the function-under-test
    pcap_set_immediate_mode(pcap_handle, immediate_mode);

    // Process the data as if it were a packet
    if (size > sizeof(struct pcap_pkthdr)) {
        struct pcap_pkthdr header;
        header.caplen = size - sizeof(struct pcap_pkthdr);
        header.len = size - sizeof(struct pcap_pkthdr);
        const uint8_t *packet_data = data + sizeof(struct pcap_pkthdr);

        // Simulate processing a packet
        pcap_dispatch(pcap_handle, 1, (pcap_handler)pcap_dump, (u_char *)packet_data);
    }

    // Close the pcap handle
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

    LLVMFuzzerTestOneInput_8(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
