#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h> // Added for close() and remove()
#include <netinet/in.h> // Added for IP header structures
#include <netinet/ip.h> // Added for struct ip

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    if (size < sizeof(struct pcap_pkthdr)) {
        // If the size is less than the pcap header, return early
        return 0;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_dead(DLT_RAW, 65535);
    if (pcap == NULL) {
        return 0;
    }

    pcap_dumper_t *dumper = pcap_dump_open(pcap, "/dev/null");
    if (dumper == NULL) {
        pcap_close(pcap);
        return 0;
    }

    // Create a pcap_pkthdr and use the input data
    struct pcap_pkthdr header;
    header.ts.tv_sec = 0;
    header.ts.tv_usec = 0;
    header.caplen = size;
    header.len = size;

    // Write the packet data to the dumper
    pcap_dump((u_char *)dumper, &header, data);

    // Apply a filter to process the packet data
    struct bpf_program fp;
    if (pcap_compile(pcap, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == 0) {
        if (pcap_setfilter(pcap, &fp) == 0) {
            // Process the packet data
            const u_char *packet;
            struct pcap_pkthdr *pkt_header;
            if (pcap_next_ex(pcap, &pkt_header, &packet) >= 0) {
                // Do something meaningful with the packet
                // For example, parse the IP header
                struct ip *ip_header = (struct ip *)(packet);
                printf("IP version: %d\n", ip_header->ip_v);
                printf("IP header length: %d\n", ip_header->ip_hl);
            }
        }
        pcap_freecode(&fp);
    }

    // Call the function-under-test
    pcap_dump_close(dumper);

    pcap_close(pcap);

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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
