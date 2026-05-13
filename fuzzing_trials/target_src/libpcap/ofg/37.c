#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define a temporary file path for the pcap dumper
#define TEMP_PCAP_FILE "/tmp/fuzz_pcap.pcap"

// Initialize the pcap dumper with a temporary file
pcap_dumper_t* initialize_pcap_dumper(pcap_t **pcap_handle) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open a dummy pcap handle (in memory)
    *pcap_handle = pcap_open_dead(DLT_EN10MB, 65535);
    if (*pcap_handle == NULL) {
        fprintf(stderr, "Failed to open pcap handle\n");
        return NULL;
    }

    // Open a dumper file
    pcap_dumper_t *dumper = pcap_dump_open(*pcap_handle, TEMP_PCAP_FILE);
    if (dumper == NULL) {
        fprintf(stderr, "Failed to open pcap dumper: %s\n", pcap_geterr(*pcap_handle));
        pcap_close(*pcap_handle);
        return NULL;
    }

    return dumper;
}

void packet_handler_37(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // Function to process each packet
    // For demonstration, we will just print the packet length
    printf("Packet length: %u\n", h->len);
}

int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Initialize the pcap dumper
    pcap_t *pcap_handle;
    pcap_dumper_t *dumper = initialize_pcap_dumper(&pcap_handle);
    if (dumper == NULL) {
        return 0;
    }

    // Use the input data to write a pcap packet
    struct pcap_pkthdr header;
    header.ts.tv_sec = 0;
    header.ts.tv_usec = 0;
    header.caplen = size;
    header.len = size;

    // Write the packet data to the dumper
    pcap_dump((u_char *)dumper, &header, data);

    // Flush the dumper to ensure data is written to disk
    pcap_dump_flush(dumper);

    // Clean up and close the dumper
    pcap_dump_close(dumper);
    pcap_close(pcap_handle);

    // Re-open the pcap file for reading
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_read_handle = pcap_open_offline(TEMP_PCAP_FILE, errbuf);
    if (pcap_read_handle == NULL) {
        fprintf(stderr, "Failed to open pcap file for reading: %s\n", errbuf);
        remove(TEMP_PCAP_FILE);
        return 0;
    }

    // Process the packets using pcap_dispatch
    pcap_dispatch(pcap_read_handle, -1, packet_handler_37, NULL);

    // Close the read handle
    pcap_close(pcap_read_handle);

    // Remove the temporary file
    remove(TEMP_PCAP_FILE);

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

    LLVMFuzzerTestOneInput_37(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
