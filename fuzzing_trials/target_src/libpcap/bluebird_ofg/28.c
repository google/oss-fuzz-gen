#include <sys/stat.h>
#include "pcap/pcap.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h> // Include for close() and unlink()
#include "fcntl.h"  // Include for mkstemp()

int LLVMFuzzerTestOneInput_28(const uint8_t *data, size_t size) {
    pcap_t *pcap;
    struct pcap_pkthdr header;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *packet;

    // Ensure the input data is not empty
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to hold the pcap data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the input data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }

    // Close the file descriptor
    close(fd);

    // Open the pcap file
    pcap = pcap_open_offline(tmpl, errbuf);
    if (pcap == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Call the function-under-test
    packet = pcap_next(pcap, &header);

    // Clean up
    pcap_close(pcap);
    unlink(tmpl);

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

    LLVMFuzzerTestOneInput_28(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
