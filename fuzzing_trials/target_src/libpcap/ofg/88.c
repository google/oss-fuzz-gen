#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_88(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the parameters
    if (size < 10) {
        return 0;
    }

    // Initialize parameters for pcap_open_live
    char device[7];
    int snaplen = (int)data[0];  // Snap length
    int promisc = (int)data[1];  // Promiscuous mode
    int to_ms = (int)data[2];    // Read timeout in milliseconds
    char errbuf[PCAP_ERRBUF_SIZE];

    // Copy data into device name (ensuring null termination)
    memcpy(device, data + 3, 6);
    device[6] = '\0';

    // Call the function-under-test
    pcap_t *handle = pcap_open_live(device, snaplen, promisc, to_ms, errbuf);

    // Clean up
    if (handle != NULL) {
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

    LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
