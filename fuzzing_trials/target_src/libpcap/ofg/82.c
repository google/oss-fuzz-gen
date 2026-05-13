#include <stdio.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h> // Include this for the close() function

int LLVMFuzzerTestOneInput_82(const uint8_t *data, size_t size) {
    // Create a temporary file to write the fuzzing data
    char tmpl[] = "/tmp/fuzzfileXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd == -1) {
        return 0;
    }

    // Write the fuzzing data to the temporary file
    FILE *file = fdopen(fd, "wb");
    if (file == NULL) {
        close(fd);
        return 0;
    }
    fwrite(data, 1, size, file);
    fclose(file);

    // Re-open the file for reading
    file = fopen(tmpl, "rb");
    if (file == NULL) {
        return 0;
    }

    // Define a buffer for error messages
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    // Use a fixed timestamp precision value for testing
    u_int tstamp_precision = PCAP_TSTAMP_PRECISION_MICRO;

    // Call the function-under-test
    pcap_t *pcap = pcap_fopen_offline_with_tstamp_precision(file, tstamp_precision, errbuf);

    // Clean up
    if (pcap != NULL) {
        pcap_close(pcap);
    }
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

    LLVMFuzzerTestOneInput_82(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
