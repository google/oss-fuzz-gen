#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_100(const uint8_t *data, size_t size) {
    pcap_t *pcap_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int datalink_type;

    // Initialize pcap handle using pcap_open_dead for fuzzing
    pcap_handle = pcap_open_dead(DLT_EN10MB, 65535); // Ethernet and max snaplen

    if (pcap_handle == NULL) {
        return 0;
    }

    // Ensure the size is sufficient to extract an integer for datalink_type
    if (size >= sizeof(int)) {
        datalink_type = *((int *)data);
    } else {
        datalink_type = DLT_EN10MB; // Default to Ethernet if not enough data
    }

    // Call the function-under-test
    pcap_set_datalink(pcap_handle, datalink_type);

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

    LLVMFuzzerTestOneInput_100(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
