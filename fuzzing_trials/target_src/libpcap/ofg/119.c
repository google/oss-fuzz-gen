#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_119(const uint8_t *data, size_t size) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Ensure errbuf is null-terminated
    if (size < PCAP_ERRBUF_SIZE) {
        memcpy(errbuf, data, size);
        errbuf[size] = '\0';
    } else {
        memcpy(errbuf, data, PCAP_ERRBUF_SIZE - 1);
        errbuf[PCAP_ERRBUF_SIZE - 1] = '\0';
    }

    // Call the function-under-test
    int result = pcap_findalldevs(&alldevs, errbuf);

    // Clean up if devices were found
    if (result == 0 && alldevs != NULL) {
        pcap_freealldevs(alldevs);
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

    LLVMFuzzerTestOneInput_119(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
