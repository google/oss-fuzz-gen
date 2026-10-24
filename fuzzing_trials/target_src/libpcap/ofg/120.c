#include <stdint.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Define a callback function to process packets
void packet_handler_120(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // For fuzzing purposes, we can print the packet length
    // and examine the first few bytes of the packet
    (void)user; // Unused parameter
    printf("Packet length: %u\n", pkthdr->len);

    // Print the first few bytes of the packet for examination
    size_t print_len = pkthdr->len < 16 ? pkthdr->len : 16;
    printf("Packet data (first %zu bytes): ", print_len);
    for (size_t i = 0; i < print_len; ++i) {
        printf("%02x ", packet[i]);
    }
    printf("\n");
}

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Define and initialize variables for the function parameters
    int linktype = DLT_EN10MB; // Ethernet, commonly used link-layer type
    int snaplen = 65535; // Maximum number of bytes to capture per packet

    // Call the function-under-test
    pcap_t *pcap_handle = pcap_open_dead(linktype, snaplen);

    // Check if the pcap handle is not NULL
    if (pcap_handle != NULL) {
        // Create a pcap_pkthdr structure to pass to the packet handler
        struct pcap_pkthdr header;
        header.caplen = size;
        header.len = size;

        // Use the input data to simulate a packet capture
        if (size > 0) {
            // Directly call the packet handler with the input data
            packet_handler_120(NULL, &header, data);
        }

        // Close the pcap handle
        pcap_close(pcap_handle);
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

    LLVMFuzzerTestOneInput_120(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
