#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function to create a dummy Ethernet frame
void create_dummy_packet(uint8_t *packet, size_t size) {
    if (size < 14) return; // Minimum Ethernet frame size

    // Destination MAC address (broadcast)
    memset(packet, 0xFF, 6);

    // Source MAC address (random)
    for (int i = 6; i < 12; i++) {
        packet[i] = rand() % 256;
    }

    // EtherType (IPv4)
    packet[12] = 0x08;
    packet[13] = 0x00;

    // Fill the rest with random data
    for (size_t i = 14; i < size; i++) {
        packet[i] = rand() % 256;
    }
}

int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Create a dummy pcap_t handle for testing
    handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == NULL) {
        return 0;
    }

    // Ensure size is non-zero and within a reasonable range
    if (size < 14 || size > 65535) {
        pcap_close(handle);
        return 0;
    }

    // Create a dummy packet
    uint8_t *packet = (uint8_t *)malloc(size);
    if (!packet) {
        pcap_close(handle);
        return 0;
    }
    create_dummy_packet(packet, size);

    // Call the function-under-test
    pcap_sendpacket(handle, packet, (int)size);

    // Clean up
    free(packet);
    pcap_close(handle);

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

    LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
