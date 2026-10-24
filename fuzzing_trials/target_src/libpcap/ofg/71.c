#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_71(const uint8_t *data, size_t size) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int packet_size;

    // Ensure size is not zero to avoid passing a NULL pointer
    if (size == 0) {
        return 0;
    }

    // Open a fake pcap handle for testing purposes
    handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (handle == NULL) {
        return 0;
    }

    // Use the first byte of data to determine a packet size
    packet_size = (size > 1) ? data[0] : 1;
    if (packet_size > size) {
        packet_size = size;
    }

    // Call the function-under-test
    pcap_sendpacket(handle, data, packet_size);

    // Close the pcap handle
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

    LLVMFuzzerTestOneInput_71(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
