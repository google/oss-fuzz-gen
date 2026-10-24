#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>

// Fuzzing harness for pcap_dump_ftell64
int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    // Initialize pcap_t and pcap_dumper_t
    pcap_t *pcap;
    pcap_dumper_t *dumper;
    char errbuf[PCAP_ERRBUF_SIZE];
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    // Check if file descriptor creation was successful
    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the temporary file
    write(fd, data, size);
    close(fd);

    // Open the temporary file as a pcap file
    pcap = pcap_open_offline(tmpl, errbuf);
    if (pcap == NULL) {
        return 0;
    }

    // Open a dumper to write packets to a file
    dumper = pcap_dump_open(pcap, tmpl);
    if (dumper == NULL) {
        pcap_close(pcap);
        return 0;
    }

    // Call the function-under-test
    int64_t result = pcap_dump_ftell64(dumper);

    // Clean up
    pcap_dump_close(dumper);
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

    LLVMFuzzerTestOneInput_102(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
