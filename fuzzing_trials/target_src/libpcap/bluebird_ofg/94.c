#include <sys/stat.h>
#include "pcap/pcap.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>  // Include for close() and write() functions
#include "fcntl.h"   // Include for mkstemp() function

// Define the callback function for packet processing outside of LLVMFuzzerTestOneInput
void packet_handler_94(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Process the packet (this is where you would add the logic to test)
    (void)user;
    (void)pkthdr;
    (void)packet;
}

int LLVMFuzzerTestOneInput_94(const uint8_t *data, size_t size) {
    // Create a temporary file to simulate a pcap file
    char tmpl[] = "/tmp/fuzzpcapXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the temporary file for reading as a pcap file
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(tmpl, errbuf);
    if (pcap == NULL) {
        remove(tmpl);
        return 0;
    }

    // Process packets using pcap_loop
    pcap_loop(pcap, 0, packet_handler_94, NULL);

    // Clean up
    pcap_close(pcap);
    remove(tmpl);

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

    LLVMFuzzerTestOneInput_94(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
