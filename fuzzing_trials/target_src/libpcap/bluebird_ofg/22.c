#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "pcap/pcap.h"
#include <string.h>

int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for extracting an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the data for the promisc parameter
    int promisc = *((int *)data);

    // Create a pcap_t structure using pcap_create and pcap_activate
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_create("lo", errbuf); // Using "lo" (loopback) as a dummy device
    if (pcap == NULL) {
        return 0; // If pcap_create fails, return 0
    }

    // Activate the pcap_t
    if (pcap_activate(pcap) != 0) {
        pcap_close(pcap);
        return 0; // If pcap_activate fails, return 0
    }

    // Call the function-under-test
    int result = pcap_set_promisc(pcap, promisc);

    // Clean up
    pcap_close(pcap);

    // Return 0 as required by the fuzzer
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
