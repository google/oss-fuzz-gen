#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "pcap/pcap.h"
#include <sys/time.h> // Include for struct timeval
#include <string.h>   // Include for memcpy

// Define a simple packet handler function
void packet_handler_48(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // For demonstration purposes, simply print the packet length
    (void)user; // Avoid unused parameter warning
    if (pkthdr != NULL) {
        printf("Packet length: %u\n", pkthdr->len);
    }
    // Normally, you would process the packet here
}

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Declare and initialize a pcap_t pointer
    pcap_t *pcap_handle = pcap_open_dead(DLT_RAW, 65535);
    if (pcap_handle == NULL) {
        return 0;
    }

    // Check if the size of data is sufficient for a pcap packet header
    if (size < sizeof(struct pcap_pkthdr)) {
        pcap_close(pcap_handle);
        return 0;
    }

    // Create a pcap_pkthdr and copy the input data into it
    struct pcap_pkthdr header;
    memcpy(&header, data, sizeof(struct pcap_pkthdr));

    // Ensure the packet length is valid and does not exceed the remaining data size
    if (header.caplen > size - sizeof(struct pcap_pkthdr)) {
        pcap_close(pcap_handle);
        return 0;
    }

    // Use pcap_dispatch to process the packet with a packet handler
    pcap_dispatch(pcap_handle, 1, packet_handler_48, (u_char *)(data + sizeof(struct pcap_pkthdr)));

    // Clean up by closing the pcap handle
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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
