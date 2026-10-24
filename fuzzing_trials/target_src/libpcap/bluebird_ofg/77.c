#include <sys/stat.h>
#include "pcap/pcap.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>  // For close()

int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    FILE *file = fdopen(fd, "wb+");
    if (file == NULL) {
        close(fd);
        return 0;
    }

    // Write the fuzz data to the file
    fwrite(data, 1, size, file);
    fflush(file);

    // Rewind the file to the beginning
    fseek(file, 0, SEEK_SET);

    // Create a fake pcap_t handle for testing
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (pcap == NULL) {
        fclose(file);
        return 0;
    }

    // Open a pcap dumper using the file
    pcap_dumper_t *dumper = pcap_dump_fopen(pcap, file);
    if (dumper == NULL) {
        pcap_close(pcap);
        fclose(file);
        return 0;
    }

    // Call the function-under-test
    long position = pcap_dump_ftell(dumper);

    // Print the position for debugging purposes
    printf("Current position in the dump file: %ld\n", position);

    // Clean up
    pcap_dump_close(dumper);  // This will also close the file
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

    LLVMFuzzerTestOneInput_77(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
