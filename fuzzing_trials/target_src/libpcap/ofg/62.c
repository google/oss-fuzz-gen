#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    // Ensure the input data is not null and has a reasonable size
    if (data == NULL || size == 0) {
        return 0;
    }

    // Create a temporary file to simulate a pcap file
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

    // Open the pcap file from the temporary file descriptor
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle = pcap_fopen_offline(temp_file, errbuf);
    if (pcap_handle == NULL) {
        fclose(temp_file);
        return 0;
    }

    // Declare the timestamp types array
    int *tstamp_types = NULL;

    // Call the function-under-test
    int result = pcap_list_tstamp_types(pcap_handle, &tstamp_types);

    // Free the timestamp types array if it was allocated
    if (tstamp_types != NULL) {
        free(tstamp_types);
    }

    // Close the pcap handle
    pcap_close(pcap_handle);

    // Close the temporary file
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

    LLVMFuzzerTestOneInput_62(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
