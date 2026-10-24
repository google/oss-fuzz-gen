#include <stdint.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>

int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    // Initialize a pcap_t structure
    char errbuf[PCAP_ERRBUF_SIZE];

    // Ensure size is at least large enough to simulate a pcap file header
    if (size < sizeof(struct pcap_file_header)) {
        return 0;
    }

    // Create a temporary file to simulate a pcap file
    FILE *temp_file = tmpfile();
    if (temp_file == NULL) {
        return 0;
    }

    // Write the data to the temporary file
    if (fwrite(data, 1, size, temp_file) != size) {
        fclose(temp_file);
        return 0;
    }

    // Rewind the file to the beginning
    rewind(temp_file);

    // Open the temporary file as a pcap file
    pcap_t *pcap_handle = pcap_fopen_offline(temp_file, errbuf);
    if (pcap_handle == NULL) {
        fclose(temp_file);
        return 0;
    }

    // Use the first byte of data as the integer parameter for pcap_set_rfmon
    int rfmon = data[0] % 2; // Ensure it's either 0 or 1

    // Call the function-under-test
    pcap_set_rfmon(pcap_handle, rfmon);

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

    LLVMFuzzerTestOneInput_97(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
