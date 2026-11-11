#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "pcap/pcap.h"
#include <string.h>

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    pcap_t *pcap_handle;
    int *tstamp_types = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Create a temporary file to store the input data
    FILE *temp_file = tmpfile();
    if (temp_file == NULL) {
        return 0;
    }

    // Write the fuzzer data to the temporary file
    if (fwrite(data, 1, size, temp_file) != size) {
        fclose(temp_file);
        return 0;
    }

    // Rewind the file to the beginning for reading
    rewind(temp_file);

    // Get the file descriptor of the temporary file
    int fd = fileno(temp_file);
    if (fd == -1) {
        fclose(temp_file);
        return 0;
    }

    // Open the pcap handle using the temporary file descriptor
    pcap_handle = pcap_fopen_offline(fdopen(fd, "rb"), errbuf);
    if (pcap_handle == NULL) {
        fclose(temp_file);
        return 0;
    }

    // Call the function-under-test
    pcap_list_tstamp_types(pcap_handle, &tstamp_types);

    // Clean up
    if (tstamp_types != NULL) {
        free(tstamp_types);
    }
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

    LLVMFuzzerTestOneInput_34(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
