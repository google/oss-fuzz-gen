#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "pcap/pcap.h"
#include <string.h>

int LLVMFuzzerTestOneInput_4(const uint8_t *data, size_t size) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Ensure we have enough data to set a device name
    if (size < 1) {
        return 0;
    }

    // Use the input data to create a device name
    char device[256];
    size_t device_len = size < sizeof(device) ? size : sizeof(device) - 1;
    memcpy(device, data, device_len);
    device[device_len] = '\0'; // Null-terminate the string

    // Initialize a pcap_t structure with pcap_create
    handle = pcap_create(device, errbuf);
    if (handle == NULL) {
        return 0;
    }

    // Set some non-NULL options to the pcap_t structure
    pcap_set_snaplen(handle, 65535); // Set the snapshot length
    pcap_set_promisc(handle, 1);     // Set promiscuous mode
    pcap_set_timeout(handle, 1000);  // Set read timeout

    // Call the function-under-test
    int result = pcap_activate(handle);

    // Clean up
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

    LLVMFuzzerTestOneInput_4(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
