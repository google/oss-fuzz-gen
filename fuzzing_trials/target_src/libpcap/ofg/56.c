#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h> // Include for close()

int LLVMFuzzerTestOneInput_56(const uint8_t *data, size_t size) {
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    // Check for pcap file magic numbers
    uint32_t magic_number = *((uint32_t *)data);
    if (magic_number != 0xa1b2c3d4 && magic_number != 0xd4c3b2a1 &&
        magic_number != 0xa1b23c4d && magic_number != 0x4d3cb2a1) {
        return 0;
    }

    // Create a temporary file to write the fuzzing data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }

    fwrite(data, 1, size, file);
    fflush(file);
    rewind(file);

    // Prepare a dummy error buffer
    char errbuf[PCAP_ERRBUF_SIZE];
    memset(errbuf, 0, sizeof(errbuf));

    // Call the function-under-test
    pcap_t *pcap = pcap_fopen_offline(file, errbuf);

    // Check if pcap is NULL and log error
    if (pcap == NULL) {
        fprintf(stderr, "pcap_fopen_offline error: %s\n", errbuf);
    } else {
        // If pcap is valid, perform additional operations to increase coverage
        // Example: pcap_loop(pcap, 0, packet_handler, NULL);
        pcap_close(pcap);
    }

    // Clean up
    fclose(file);
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

    LLVMFuzzerTestOneInput_56(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
