#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

// Define a packet handler function
void packet_handler_53(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    // Do nothing with the packet data
}

int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];
    int packet_count_limit = 10; // Arbitrary non-negative value
    int timeout_limit = 1000;    // Arbitrary non-negative value in milliseconds

    // Create a temporary file to store the pcap data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    if (write(fd, data, size) != size) {
        close(fd);
        unlink(tmpl);
        return 0;
    }
    close(fd);

    // Open the pcap file
    pcap = pcap_open_offline(tmpl, errbuf);
    if (pcap == NULL) {
        unlink(tmpl);
        return 0;
    }

    // Allocate some user data
    u_char user_data[10];
    memset(user_data, 0, sizeof(user_data));

    // Call the function-under-test
    int result = pcap_loop(pcap, packet_count_limit, packet_handler_53, user_data);
    (void)result; // Suppress unused variable warning

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

    LLVMFuzzerTestOneInput_53(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
