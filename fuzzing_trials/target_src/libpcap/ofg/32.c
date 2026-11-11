#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

int LLVMFuzzerTestOneInput_32(const uint8_t *data, size_t size) {
    pcap_t *pcap_handle;
    char errbuf[PCAP_ERRBUF_SIZE];

    // Ensure the data size is sufficient to create a pcap_t structure
    if (size < 24) { // Minimum size for pcap_open_offline
        return 0;
    }

    // Create a temporary file to store the input data
    FILE *temp_file = tmpfile();
    if (temp_file == NULL) {
        return 0;
    }

    // Write the input data to the temporary file
    if (fwrite(data, 1, size, temp_file) != size) {
        fclose(temp_file);
        return 0;
    }

    // Rewind the file to the beginning
    rewind(temp_file);

    // Get the file descriptor of the temporary file
    int fd = fileno(temp_file);

    // Use pcap_fopen_offline to create a pcap_t structure from the file descriptor
    pcap_handle = pcap_fopen_offline(fdopen(fd, "rb"), errbuf);
    if (pcap_handle == NULL) {
        fclose(temp_file);
        return 0;
    }

    // Call the function-under-test
    int precision = pcap_get_tstamp_precision(pcap_handle);

    // Clean up
    pcap_close(pcap_handle);
    fclose(temp_file);

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

    LLVMFuzzerTestOneInput_32(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
