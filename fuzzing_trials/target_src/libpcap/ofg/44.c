#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    pcap_t *pcap;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Ensure that the data is not empty
    if (size == 0) {
        return 0;
    }

    // Create a temporary file to store the pcap data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }
    FILE *f = fdopen(fd, "wb");
    if (f == NULL) {
        close(fd);
        return 0;
    }

    // Write the fuzz data to the temporary file
    fwrite(data, 1, size, f);
    fclose(f);

    // Open the pcap file
    pcap = pcap_open_offline(tmpl, errbuf);
    if (pcap == NULL) {
        remove(tmpl);
        return 0;
    }

    // Call the function-under-test
    FILE *file = pcap_file(pcap);

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

    LLVMFuzzerTestOneInput_44(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
