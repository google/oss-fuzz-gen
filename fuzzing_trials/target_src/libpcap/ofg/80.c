#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>

extern int pcap_set_protocol_linux(pcap_t *, int);

int LLVMFuzzerTestOneInput_80(const uint8_t *data, size_t size) {
    pcap_t *pcap_handle;
    int protocol;

    // Ensure size is sufficient to extract an int for protocol
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize pcap_t handle (dummy initialization for fuzzing)
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcap_handle == NULL) {
        return 0;
    }

    // Extract protocol from data
    protocol = *((int *)data);

    // Call the function-under-test
    pcap_set_protocol_linux(pcap_handle, protocol);

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

    LLVMFuzzerTestOneInput_80(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
