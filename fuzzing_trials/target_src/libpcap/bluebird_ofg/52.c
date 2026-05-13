#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "pcap/pcap.h"

extern int pcap_set_protocol_linux(pcap_t *, int);

int LLVMFuzzerTestOneInput_52(const uint8_t *data, size_t size) {
    pcap_t *pcap_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int protocol;

    // Ensure data size is sufficient for extracting an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Initialize pcap handle
    pcap_handle = pcap_create("any", errbuf);
    if (pcap_handle == NULL) {
        return 0;
    }

    // Set the protocol using the first 4 bytes of the input data
    protocol = *(int *)data;

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

    LLVMFuzzerTestOneInput_52(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
