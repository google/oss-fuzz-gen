#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_65(const uint8_t *data, size_t size) {
    // Initialize a pcap_t structure
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_dead(DLT_EN10MB, 65535);

    if (handle == NULL) {
        return 0;
    }

    // Create a pcap packet header
    struct pcap_pkthdr header;
    header.ts.tv_sec = 0;
    header.ts.tv_usec = 0;
    header.caplen = size;
    header.len = size;

    // Feed the data into pcap functions
    if (size > 0) {
        const u_char *packet = data;
        pcap_dump((u_char *)pcap_dump_open(handle, "/dev/null"), &header, packet);
    }

    // Call the function-under-test
    int fd = pcap_get_selectable_fd(handle);

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

    LLVMFuzzerTestOneInput_65(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
