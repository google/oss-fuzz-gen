#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <unistd.h>
#include <fcntl.h>

int LLVMFuzzerTestOneInput_79(const uint8_t *data, size_t size) {
    pcap_dumper_t *dumper;
    FILE *file;
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);

    if (fd == -1) {
        return 0;
    }

    // Write the fuzz data to the file
    if (write(fd, data, size) == -1) {
        close(fd);
        return 0;
    }
    
    // Close the file descriptor
    close(fd);

    // Open the file with pcap_dump_open
    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcap == NULL) {
        return 0;
    }

    dumper = pcap_dump_open(pcap, tmpl);
    if (dumper == NULL) {
        pcap_close(pcap);
        return 0;
    }

    // Call the function-under-test
    file = pcap_dump_file(dumper);

    // Clean up
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

    LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
